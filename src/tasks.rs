//! Background Tasks management module for vibe-daemon.
//! Enables asynchronous execution of long-running commands (builds, tests, compiles)
//! without blocking the main MCP JSON-RPC protocol thread.
//! Provides real-time status monitoring, smart log output extraction, and cancellation.

use crate::config::TasksConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info};

/// Default maximum in-memory output buffer size per background task (5 MB) to prevent OOM.
pub const MAX_TASK_OUTPUT_BYTES: usize = 5 * 1024 * 1024;

static TASK_COUNTER: AtomicU64 = AtomicU64::new(1);

// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------

/// Status of a background task lifecycle with strict state machine validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    Running,
    Cancelling,
    Success,
    Failed,
    Cancelled,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::Cancelling => write!(f, "Cancelling"),
            Self::Success => write!(f, "Success"),
            Self::Failed => write!(f, "Failed"),
            Self::Cancelled => write!(f, "Cancelled"),
        }
    }
}

impl TaskStatus {
    /// Returns true if the task is in a terminal state (cannot transition further).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Success | Self::Failed | Self::Cancelled)
    }

    /// Returns true if the task is active (currently running or in progress of cancelling).
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Running | Self::Cancelling)
    }

    /// Validates if transition from `self` to `next` is permitted.
    /// Strictly enforces:
    /// - Running -> Success
    /// - Running -> Failed
    /// - Running -> Cancelling
    /// - Cancelling -> Cancelled
    pub fn can_transition_to(&self, next: TaskStatus) -> bool {
        matches!(
            (self, next),
            (Self::Running, Self::Success)
                | (Self::Running, Self::Failed)
                | (Self::Running, Self::Cancelling)
                | (Self::Cancelling, Self::Cancelled)
        )
    }
}

/// Structured status report returned by `check_task_status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskStatusReport {
    pub task_id: String,
    pub command: String,
    pub status: TaskStatus,
    pub exit_code: Option<i32>,
    pub start_time: String,
    pub duration_seconds: f64,
}

/// Internal state of a registered background task.
#[derive(Debug)]
pub struct BackgroundTaskInternal {
    pub id: String,
    pub command: String,
    pub status: TaskStatus,
    pub exit_code: Option<i32>,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub output_buffer: Arc<tokio::sync::Mutex<Vec<u8>>>,
    pub cancel_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl BackgroundTaskInternal {
    /// Attempts to transition the task status to `next`.
    /// Returns `true` if transition was permitted and performed, `false` otherwise.
    pub fn transition_to(&mut self, next: TaskStatus) -> bool {
        if self.status.can_transition_to(next) {
            self.status = next;
            true
        } else {
            false
        }
    }
}

/// Gracefully terminates a child process and its entire process tree/group.
/// Guarantees that `child.wait()` is called to prevent zombie processes.
async fn kill_process_tree(
    child: &mut tokio::process::Child,
    pid_opt: Option<u32>,
    grace: Duration,
) {
    #[cfg(unix)]
    {
        if let Some(pid) = pid_opt {
            let pgid = pid as libc::pid_t;
            // 1. Send SIGTERM to the process group (-pgid)
            unsafe {
                libc::kill(-pgid, libc::SIGTERM);
            }
            // 2. Await process exit within grace duration
            match tokio::time::timeout(grace, child.wait()).await {
                Ok(Ok(_)) => return,
                _ => {
                    // 3. Fallback: forcefully send SIGKILL to the process group
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                }
            }
        } else {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }

    #[cfg(windows)]
    {
        let _ = grace;
        if let Some(pid) = pid_opt {
            // taskkill /PID <pid> /T /F terminates process and all its child processes
            let _ = tokio::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .output()
                .await;
        }
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

/// Thread-safe manager for background tasks with quotas, TTL eviction, and process tree isolation.
#[derive(Debug, Clone)]
pub struct TaskManager {
    config: Arc<TasksConfig>,
    tasks:
        Arc<tokio::sync::RwLock<HashMap<String, Arc<tokio::sync::RwLock<BackgroundTaskInternal>>>>>,
    event_bus: Option<Arc<crate::events::EventBus>>,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskManager {
    /// Create a new TaskManager with default task configuration.
    pub fn new() -> Self {
        Self::with_config(TasksConfig::default())
    }

    /// Create a new TaskManager with the specified task configuration.
    pub fn with_config(config: TasksConfig) -> Self {
        Self {
            config: Arc::new(config),
            tasks: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            event_bus: None,
        }
    }

    /// Associate an EventBus for server-initiated task completion notifications.
    pub fn with_event_bus(mut self, event_bus: Arc<crate::events::EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Set or update the EventBus instance.
    pub fn set_event_bus(&mut self, event_bus: Arc<crate::events::EventBus>) {
        self.event_bus = Some(event_bus);
    }

    /// Returns a reference to the active tasks configuration.
    pub fn config(&self) -> &TasksConfig {
        &self.config
    }

    /// Internal eviction of completed tasks older than `completed_ttl_secs` and enforcement of `max_retained_tasks`.
    async fn cleanup_internal(
        config: &TasksConfig,
        tasks_map: &mut HashMap<String, Arc<tokio::sync::RwLock<BackgroundTaskInternal>>>,
    ) {
        let now = chrono::Utc::now();
        let ttl_duration = chrono::Duration::seconds(config.completed_ttl_secs as i64);

        // 1. Evict completed tasks exceeding completed_ttl_secs
        let mut expired_ids = Vec::new();
        for (id, task_arc) in tasks_map.iter() {
            let task = task_arc.read().await;
            if task.status.is_terminal() {
                let finished_at = task.end_time.unwrap_or(task.start_time);
                if now.signed_duration_since(finished_at) > ttl_duration {
                    expired_ids.push(id.clone());
                }
            }
        }
        for id in expired_ids {
            tasks_map.remove(&id);
        }

        // 2. Enforce max_retained_tasks by removing oldest completed tasks
        if tasks_map.len() > config.max_retained_tasks {
            let mut completed_tasks = Vec::new();
            for (id, task_arc) in tasks_map.iter() {
                let task = task_arc.read().await;
                if task.status.is_terminal() {
                    let finished_at = task.end_time.unwrap_or(task.start_time);
                    completed_tasks.push((id.clone(), finished_at));
                }
            }

            // Sort oldest completed first
            completed_tasks.sort_by_key(|(_, finished)| *finished);

            let excess = tasks_map.len().saturating_sub(config.max_retained_tasks);
            let to_remove = excess.min(completed_tasks.len());
            for (id, _) in completed_tasks.into_iter().take(to_remove) {
                tasks_map.remove(&id);
            }
        }
    }

    /// Explicitly triggers TTL eviction and max retained tasks pruning.
    pub async fn cleanup_tasks(&self) {
        let mut tasks_map = self.tasks.write().await;
        Self::cleanup_internal(&self.config, &mut tasks_map).await;
    }

    /// Generate a unique task identifier.
    fn generate_task_id() -> String {
        let count = TASK_COUNTER.fetch_add(1, Ordering::Relaxed);
        let millis = chrono::Utc::now().timestamp_millis();
        format!("task-{millis}-{count:04x}")
    }
    /// Start a new background process for the given command string.
    /// Spawns an asynchronous Tokio worker and immediately returns task details with `task_id`.
    /// Enforces `max_active_tasks` quota and triggers TTL/retention cleanup.
    pub async fn start_task(&self, command: &str) -> Result<String, String> {
        let trimmed_cmd = command.trim();
        if trimmed_cmd.is_empty() {
            return Err("Command cannot be empty".to_string());
        }

        let mut tasks_map = self.tasks.write().await;

        // 1. Evict expired and excess tasks before quota validation
        Self::cleanup_internal(&self.config, &mut tasks_map).await;

        // 2. Count active tasks and enforce max_active_tasks quota
        let mut active_count = 0;
        for task_arc in tasks_map.values() {
            let task = task_arc.read().await;
            if task.status.is_active() {
                active_count += 1;
            }
        }

        if active_count >= self.config.max_active_tasks {
            return Err(format!(
                "Maximum active background tasks limit reached ({active_count}/{}). Wait for running tasks to finish or cancel existing tasks.",
                self.config.max_active_tasks
            ));
        }

        let task_id = Self::generate_task_id();

        let mut process_cmd = if cfg!(windows) {
            let mut c = tokio::process::Command::new("cmd");
            c.args(["/C", trimmed_cmd]);
            c
        } else {
            let mut c = tokio::process::Command::new("sh");
            c.args(["-c", trimmed_cmd]);
            c
        };

        #[cfg(unix)]
        {
            process_cmd.process_group(0);
        }

        process_cmd.stdout(std::process::Stdio::piped());
        process_cmd.stderr(std::process::Stdio::piped());

        let mut child = process_cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn process for command '{trimmed_cmd}': {e}"))?;

        let child_pid = child.id();
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let output_buffer = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let now = chrono::Utc::now();

        let task_internal = Arc::new(tokio::sync::RwLock::new(BackgroundTaskInternal {
            id: task_id.clone(),
            command: trimmed_cmd.to_string(),
            status: TaskStatus::Running,
            exit_code: None,
            start_time: now,
            end_time: None,
            output_buffer: output_buffer.clone(),
            cancel_sender: Some(cancel_tx),
        }));

        tasks_map.insert(task_id.clone(), task_internal.clone());
        drop(tasks_map);

        info!(task_id = %task_id, command = %trimmed_cmd, "Started background task");

        // Spawn asynchronous supervisor task
        let worker_task_id = task_id.clone();
        let worker_task_internal = task_internal.clone();
        let worker_buffer = output_buffer.clone();
        let output_limit = self.config.output_limit_bytes;
        let grace_duration = Duration::from_secs(self.config.termination_grace_secs);
        let worker_event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();

            let buf_stdout = worker_buffer.clone();
            let stdout_reader = tokio::spawn(async move {
                if let Some(mut out) = stdout {
                    let mut chunk = [0u8; 4096];
                    while let Ok(n) = out.read(&mut chunk).await {
                        if n == 0 {
                            break;
                        }
                        let mut b = buf_stdout.lock().await;
                        if b.len() + n <= output_limit {
                            b.extend_from_slice(&chunk[..n]);
                        } else if b.len() < output_limit {
                            let rem = output_limit - b.len();
                            b.extend_from_slice(&chunk[..rem]);
                            b.extend_from_slice(
                                b"\n[Output truncated: maximum buffer limit reached]\n",
                            );
                        }
                    }
                }
            });

            let buf_stderr = worker_buffer.clone();
            let stderr_reader = tokio::spawn(async move {
                if let Some(mut err) = stderr {
                    let mut chunk = [0u8; 4096];
                    while let Ok(n) = err.read(&mut chunk).await {
                        if n == 0 {
                            break;
                        }
                        let mut b = buf_stderr.lock().await;
                        if b.len() + n <= output_limit {
                            b.extend_from_slice(&chunk[..n]);
                        } else if b.len() < output_limit {
                            let rem = output_limit - b.len();
                            b.extend_from_slice(&chunk[..rem]);
                            b.extend_from_slice(
                                b"\n[Output truncated: maximum buffer limit reached]\n",
                            );
                        }
                    }
                }
            });

            tokio::select! {
                _ = &mut cancel_rx => {
                    debug!(task_id = %worker_task_id, "Cancellation signal received; terminating process tree");
                    kill_process_tree(&mut child, child_pid, grace_duration).await;
                    let _ = stdout_reader.await;
                    let _ = stderr_reader.await;

                    let end_time = chrono::Utc::now();
                    let mut task = worker_task_internal.write().await;
                    let _ = task.transition_to(TaskStatus::Cancelled);
                    task.end_time = Some(end_time);
                    task.cancel_sender = None;
                    let mut b = worker_buffer.lock().await;
                    b.extend_from_slice(b"\n[Process cancelled by user]\n");
                    let final_status = task.status;
                    drop(task);

                    if let Some(ref bus) = worker_event_bus {
                        bus.publish_immediate(crate::events::ServerEvent::TaskCompleted {
                            task_id: worker_task_id.clone(),
                            status: final_status,
                        });
                    }
                }
                status_res = child.wait() => {
                    let _ = stdout_reader.await;
                    let _ = stderr_reader.await;

                    let end_time = chrono::Utc::now();
                    let mut task = worker_task_internal.write().await;
                    task.end_time = Some(end_time);
                    task.cancel_sender = None;

                    let (next_status, code) = match status_res {
                        Ok(status) => {
                            let code = status.code();
                            let s = if status.success() {
                                TaskStatus::Success
                            } else {
                                TaskStatus::Failed
                            };
                            (s, code)
                        }
                        Err(err) => {
                            error!(task_id = %worker_task_id, error = %err, "Error waiting on child process");
                            let mut b = worker_buffer.lock().await;
                            b.extend_from_slice(format!("\n[Process wait error: {err}]\n").as_bytes());
                            (TaskStatus::Failed, None)
                        }
                    };

                    task.exit_code = code;
                    // Strictly protect against race conditions:
                    // If task was transitioned to Cancelling or Cancelled,
                    // transition_to(next_status) returns false and avoids overwriting status.
                    if !task.transition_to(next_status) {
                        debug!(
                            task_id = %worker_task_id,
                            current_status = %task.status,
                            attempted_status = %next_status,
                            "Ignored status transition because task is cancelling or already terminal"
                        );
                    } else {
                        debug!(
                            task_id = %worker_task_id,
                            status = %task.status,
                            exit_code = ?task.exit_code,
                            "Background process finished"
                        );
                    }
                    let final_status = task.status;
                    drop(task);

                    if let Some(ref bus) = worker_event_bus {
                        bus.publish_immediate(crate::events::ServerEvent::TaskCompleted {
                            task_id: worker_task_id.clone(),
                            status: final_status,
                        });
                    }
                }
            }
        });

        let resp = serde_json::json!({
            "task_id": task_id,
            "command": trimmed_cmd,
            "status": TaskStatus::Running,
            "message": format!("Background task '{task_id}' started successfully")
        });

        serde_json::to_string_pretty(&resp).map_err(|e| format!("Serialization error: {e}"))
    }

    /// Check current execution status of a task.
    pub async fn check_status(&self, task_id: &str) -> Result<String, String> {
        let task_arc = {
            let tasks_map = self.tasks.read().await;
            tasks_map
                .get(task_id)
                .cloned()
                .ok_or_else(|| format!("Task '{task_id}' not found"))?
        };

        let task = task_arc.read().await;
        let duration_secs = task
            .end_time
            .unwrap_or_else(chrono::Utc::now)
            .signed_duration_since(task.start_time)
            .num_milliseconds() as f64
            / 1000.0;

        let report = TaskStatusReport {
            task_id: task.id.clone(),
            command: task.command.clone(),
            status: task.status,
            exit_code: task.exit_code,
            start_time: task.start_time.to_rfc3339(),
            duration_seconds: (duration_secs * 100.0).round() / 100.0,
        };

        serde_json::to_string_pretty(&report).map_err(|e| format!("Serialization error: {e}"))
    }

    /// Retrieve accumulated process output, compressed with Smart Log Engine.
    pub async fn get_output(&self, task_id: &str, lines: Option<usize>) -> Result<String, String> {
        let task_arc = {
            let tasks_map = self.tasks.read().await;
            tasks_map
                .get(task_id)
                .cloned()
                .ok_or_else(|| format!("Task '{task_id}' not found"))?
        };

        let (status, exit_code, duration_secs, raw_bytes) = {
            let task = task_arc.read().await;
            let duration = task
                .end_time
                .unwrap_or_else(chrono::Utc::now)
                .signed_duration_since(task.start_time)
                .num_milliseconds() as f64
                / 1000.0;
            let b = task.output_buffer.lock().await.clone();
            (task.status, task.exit_code, duration, b)
        };

        let raw_str = String::from_utf8_lossy(&raw_bytes);
        if raw_str.trim().is_empty() {
            return Ok(format!(
                "Task '{task_id}' [{status}, duration: {duration_secs:.2}s]: [No output recorded yet]"
            ));
        }

        // If specific line count is requested, return trailing lines with deduplication
        if let Some(n) = lines {
            let line_limit = n.clamp(1, 1000);
            let raw_lines: Vec<&str> = raw_str.lines().map(|l| l.trim_end()).collect();
            let deduped = crate::executor::deduplicate_lines(&raw_lines);
            let keep = deduped.len().min(line_limit);
            let tail = &deduped[deduped.len().saturating_sub(keep)..];
            let tail_text = tail.join("\n");

            return Ok(format!(
                "Task '{task_id}' [{status}, exit code: {:?}, duration: {duration_secs:.2}s] (last {keep} lines):\n{tail_text}",
                exit_code
            ));
        }

        // Automatic compression via Smart Log Engine
        match status {
            TaskStatus::Running | TaskStatus::Cancelling => {
                let raw_lines: Vec<&str> = raw_str.lines().map(|l| l.trim_end()).collect();
                let deduped = crate::executor::deduplicate_lines(&raw_lines);
                let keep = deduped.len().min(30);
                let tail = &deduped[deduped.len().saturating_sub(keep)..];
                let tail_text = tail.join("\n");
                Ok(format!(
                    "Task '{task_id}' [{status}, duration: {duration_secs:.2}s] (current tail):\n{tail_text}"
                ))
            }
            TaskStatus::Success => {
                let compressed =
                    crate::executor::compress_output(Some(0), duration_secs, &raw_str, "");
                Ok(format!(
                    "Task '{task_id}' [Success, duration: {duration_secs:.2}s]:\n{compressed}"
                ))
            }
            TaskStatus::Failed => {
                let code = exit_code.unwrap_or(1);
                let compressed =
                    crate::executor::compress_output(Some(code), duration_secs, &raw_str, "");
                Ok(format!(
                    "Task '{task_id}' [Failed, exit code: {code}, duration: {duration_secs:.2}s]:\n{compressed}"
                ))
            }
            TaskStatus::Cancelled => {
                let raw_lines: Vec<&str> = raw_str.lines().map(|l| l.trim_end()).collect();
                let deduped = crate::executor::deduplicate_lines(&raw_lines);
                let keep = deduped.len().min(20);
                let tail = &deduped[deduped.len().saturating_sub(keep)..];
                let tail_text = tail.join("\n");
                Ok(format!(
                    "Task '{task_id}' [Cancelled by user, duration: {duration_secs:.2}s]:\n{tail_text}"
                ))
            }
        }
    }

    /// Cancel an actively running task.
    /// Safely transitions Running -> Cancelling -> Cancelled and guarantees termination of the process tree.
    pub async fn cancel_task(&self, task_id: &str) -> Result<String, String> {
        let task_arc = {
            let tasks_map = self.tasks.read().await;
            tasks_map
                .get(task_id)
                .cloned()
                .ok_or_else(|| format!("Task '{task_id}' not found"))?
        };

        let cancel_tx = {
            let mut task = task_arc.write().await;
            if task.status != TaskStatus::Running {
                return Ok(format!(
                    "Task '{task_id}' is not currently running (status: {})",
                    task.status
                ));
            }

            if !task.transition_to(TaskStatus::Cancelling) {
                return Ok(format!(
                    "Task '{task_id}' cannot be cancelled (status: {})",
                    task.status
                ));
            }

            task.cancel_sender.take()
        };

        if let Some(tx) = cancel_tx {
            let _ = tx.send(());
        }

        // Await worker completion up to termination_grace + 2 seconds
        let max_wait = Duration::from_secs(self.config.termination_grace_secs + 2);
        let start = std::time::Instant::now();
        while start.elapsed() < max_wait {
            {
                let task = task_arc.read().await;
                if task.status == TaskStatus::Cancelled {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Ensure final status is marked as Cancelled even if worker took unusually long
        {
            let mut task = task_arc.write().await;
            if task.status == TaskStatus::Cancelling {
                let _ = task.transition_to(TaskStatus::Cancelled);
                if task.end_time.is_none() {
                    task.end_time = Some(chrono::Utc::now());
                }
            }
        }

        Ok(format!("Task '{task_id}' successfully cancelled"))
    }
}

// -----------------------------------------------------------------------------
// McpTool Implementations
// -----------------------------------------------------------------------------

use crate::mcp::protocol::CallToolResult;
use crate::tools::registry::{McpTool, ToolContext, ToolRegistry};
use async_trait::async_trait;
use tracing::warn;

pub struct StartBackgroundTaskTool;

#[async_trait]
impl McpTool for StartBackgroundTaskTool {
    fn name(&self) -> &str {
        "start_background_task"
    }

    fn description(&self) -> &str {
        "Asynchronously spawns a long-running system command in the background (builds, tests, compiles) and immediately returns a unique task_id without blocking."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "System command string to execute in the background."
                }
            },
            "required": ["command"],
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let command_arg = args.get("command").and_then(|c| c.as_str());

        match command_arg {
            Some(cmd) => {
                // 1. Guard check command safety with security config
                if let Err(violation) =
                    crate::guard::check_command_safety_with_config(cmd, &ctx.config.security)
                {
                    warn!(command = %cmd, violation = %violation, "Background task blocked by guard");
                    Ok(CallToolResult::error(format!(
                        "Security Violation: {violation}"
                    )))
                } else {
                    // 2. Check for port conflicts if command attempts to bind a port
                    let conflict_opt =
                        if let Some(port) = crate::guard::extract_port_from_command(cmd) {
                            let active_ports = crate::inspector::collect_listening_ports().await;
                            crate::guard::check_port_availability(port, &active_ports).err()
                        } else {
                            None
                        };

                    if let Some(conflict) = conflict_opt {
                        warn!(command = %cmd, conflict = %conflict, "Background task blocked due to port conflict");
                        Ok(CallToolResult::error(format!(
                            "Port Conflict Error: {}. Suggested alternative: port {}",
                            conflict.message, conflict.suggested_alternative_port
                        )))
                    } else {
                        // 3. Spawn background task asynchronously in TaskManager
                        match ctx.task_manager.start_task(cmd).await {
                            Ok(res) => Ok(CallToolResult::text(res)),
                            Err(err) => Ok(CallToolResult::error(err)),
                        }
                    }
                }
            }
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'command' must be a string",
            )),
        }
    }
}

pub struct CheckTaskStatusTool;

#[async_trait]
impl McpTool for CheckTaskStatusTool {
    fn name(&self) -> &str {
        "check_task_status"
    }

    fn description(&self) -> &str {
        "Checks the current execution status (Running, Cancelling, Success, Failed, Cancelled), exit code, and elapsed duration of a background task."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "task_id": {
                    "type": "string",
                    "description": "Unique identifier of the background task."
                }
            },
            "required": ["task_id"],
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let task_id_arg = args.get("task_id").and_then(|t| t.as_str());

        match task_id_arg {
            Some(id) => match ctx.task_manager.check_status(id).await {
                Ok(status) => Ok(CallToolResult::text(status)),
                Err(e) => Ok(CallToolResult::error(e)),
            },
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'task_id' must be a string",
            )),
        }
    }
}

pub struct GetTaskOutputTool;

#[async_trait]
impl McpTool for GetTaskOutputTool {
    fn name(&self) -> &str {
        "get_task_output"
    }

    fn description(&self) -> &str {
        "Retrieves accumulated process output for a background task, compressed and token-optimized via Smart Log Engine."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "task_id": {
                    "type": "string",
                    "description": "Unique identifier of the background task."
                },
                "lines": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "description": "Optional number of recent log lines to retrieve."
                }
            },
            "required": ["task_id"],
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let task_id_arg = args.get("task_id").and_then(|t| t.as_str());
        let lines_arg = args
            .get("lines")
            .and_then(|l| l.as_u64())
            .map(|l| l as usize);

        match task_id_arg {
            Some(id) => match ctx.task_manager.get_output(id, lines_arg).await {
                Ok(output) => Ok(CallToolResult::text(output)),
                Err(e) => Ok(CallToolResult::error(e)),
            },
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'task_id' must be a string",
            )),
        }
    }
}

pub struct CancelTaskTool;

#[async_trait]
impl McpTool for CancelTaskTool {
    fn name(&self) -> &str {
        "cancel_task"
    }

    fn description(&self) -> &str {
        "Terminates an actively running background task process immediately and marks its status as Cancelled."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "task_id": {
                    "type": "string",
                    "description": "Unique identifier of the background task to cancel."
                }
            },
            "required": ["task_id"],
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let task_id_arg = args.get("task_id").and_then(|t| t.as_str());

        match task_id_arg {
            Some(id) => match ctx.task_manager.cancel_task(id).await {
                Ok(msg) => Ok(CallToolResult::text(msg)),
                Err(e) => Ok(CallToolResult::error(e)),
            },
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'task_id' must be a string",
            )),
        }
    }
}

/// Registers the 4 background task management tools into the given registry.
pub fn register_task_tools(registry: &mut ToolRegistry) {
    registry.register_tool(StartBackgroundTaskTool);
    registry.register_tool(CheckTaskStatusTool);
    registry.register_tool(GetTaskOutputTool);
    registry.register_tool(CancelTaskTool);
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_task_lifecycle_success() {
        let manager = TaskManager::new();
        let cmd = "echo background_task_success_123";

        let start_res = manager.start_task(cmd).await.expect("Must start task");
        let v_start: serde_json::Value = serde_json::from_str(&start_res).unwrap();
        let task_id = v_start["task_id"].as_str().unwrap();

        // Wait for completion (echo is nearly instantaneous)
        let mut completed = false;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let status_res = manager.check_status(task_id).await.unwrap();
            let report: TaskStatusReport = serde_json::from_str(&status_res).unwrap();
            if report.status == TaskStatus::Success {
                assert_eq!(report.exit_code, Some(0));
                completed = true;
                break;
            }
        }
        assert!(completed, "Task should complete with Success");

        // Check output
        let output = manager.get_output(task_id, None).await.unwrap();
        assert!(output.contains("background_task_success_123"));
    }

    #[tokio::test]
    async fn test_task_lifecycle_failure() {
        let manager = TaskManager::new();
        // Guaranteed non-zero exit command
        let cmd = if cfg!(windows) {
            "cmd /C exit 42"
        } else {
            "sh -c 'exit 42'"
        };

        let start_res = manager.start_task(cmd).await.expect("Must start task");
        let v_start: serde_json::Value = serde_json::from_str(&start_res).unwrap();
        let task_id = v_start["task_id"].as_str().unwrap();

        let mut completed = false;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let status_res = manager.check_status(task_id).await.unwrap();
            let report: TaskStatusReport = serde_json::from_str(&status_res).unwrap();
            if report.status == TaskStatus::Failed {
                assert_eq!(report.exit_code, Some(42));
                completed = true;
                break;
            }
        }
        assert!(completed, "Task should complete with Failed");
    }

    #[tokio::test]
    async fn test_task_lifecycle_cancellation() {
        let manager = TaskManager::new();
        // Long running command (e.g. 10s sleep)
        let cmd = if cfg!(windows) {
            "powershell -Command \"Start-Sleep -Seconds 10\""
        } else {
            "sleep 10"
        };

        let start_res = manager.start_task(cmd).await.expect("Must start task");
        let v_start: serde_json::Value = serde_json::from_str(&start_res).unwrap();
        let task_id = v_start["task_id"].as_str().unwrap();

        // Verify it is Running
        let status_res = manager.check_status(task_id).await.unwrap();
        let report: TaskStatusReport = serde_json::from_str(&status_res).unwrap();
        assert_eq!(report.status, TaskStatus::Running);

        // Cancel it
        let cancel_res = manager.cancel_task(task_id).await.unwrap();
        assert!(cancel_res.contains("successfully cancelled"));

        // Wait a tiny bit and verify status is Cancelled
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let status_after = manager.check_status(task_id).await.unwrap();
        let report_after: TaskStatusReport = serde_json::from_str(&status_after).unwrap();
        assert_eq!(report_after.status, TaskStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_task_output_with_lines_limit() {
        let manager = TaskManager::new();
        let cmd = if cfg!(windows) {
            "for /L %i in (1,1,20) do @echo line %i"
        } else {
            "seq 1 20"
        };

        let start_res = manager.start_task(cmd).await.expect("Must start task");
        let v_start: serde_json::Value = serde_json::from_str(&start_res).unwrap();
        let task_id = v_start["task_id"].as_str().unwrap();

        // Wait for completion
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let status_res = manager.check_status(task_id).await.unwrap();
            let report: TaskStatusReport = serde_json::from_str(&status_res).unwrap();
            if report.status == TaskStatus::Success {
                break;
            }
        }

        let output_5 = manager.get_output(task_id, Some(5)).await.unwrap();
        assert!(output_5.contains("last 5 lines"));
    }

    #[tokio::test]
    async fn test_task_not_found() {
        let manager = TaskManager::new();
        assert!(manager.check_status("non_existent_id").await.is_err());
        assert!(manager.get_output("non_existent_id", None).await.is_err());
        assert!(manager.cancel_task("non_existent_id").await.is_err());
    }

    #[tokio::test]
    async fn test_task_max_active_tasks_quota() {
        let config = TasksConfig {
            max_active_tasks: 2,
            max_retained_tasks: 10,
            output_limit_bytes: 1024 * 1024,
            completed_ttl_secs: 3600,
            termination_grace_secs: 1,
        };
        let manager = TaskManager::with_config(config);

        let sleep_cmd = if cfg!(windows) {
            "powershell -Command \"Start-Sleep -Seconds 10\""
        } else {
            "sleep 10"
        };

        // Start task 1 and task 2 (quota max_active_tasks = 2)
        let res1 = manager
            .start_task(sleep_cmd)
            .await
            .expect("Task 1 should start");
        let v1: serde_json::Value = serde_json::from_str(&res1).unwrap();
        let id1 = v1["task_id"].as_str().unwrap();

        let res2 = manager
            .start_task(sleep_cmd)
            .await
            .expect("Task 2 should start");
        let v2: serde_json::Value = serde_json::from_str(&res2).unwrap();
        let id2 = v2["task_id"].as_str().unwrap();

        // Task 3 must be rejected because active tasks == 2 == max_active_tasks
        let res3 = manager.start_task(sleep_cmd).await;
        assert!(
            res3.is_err(),
            "Task 3 should be rejected due to active quota"
        );
        let err_msg = res3.unwrap_err();
        assert!(err_msg.contains("Maximum active background tasks limit reached"));

        // Cancel task 1
        manager
            .cancel_task(id1)
            .await
            .expect("Task 1 should cancel");

        // Now task 3 should start successfully because active count dropped to 1
        let res3_after = manager.start_task(sleep_cmd).await;
        assert!(res3_after.is_ok(), "Task 3 should now start successfully");
        let v3: serde_json::Value = serde_json::from_str(&res3_after.unwrap()).unwrap();
        let id3 = v3["task_id"].as_str().unwrap();

        // Cleanup remaining active tasks
        let _ = manager.cancel_task(id2).await;
        let _ = manager.cancel_task(id3).await;
    }

    #[tokio::test]
    async fn test_task_ttl_cleanup_and_max_retained() {
        let config = TasksConfig {
            max_active_tasks: 5,
            max_retained_tasks: 2,
            output_limit_bytes: 1024 * 1024,
            completed_ttl_secs: 1,
            termination_grace_secs: 1,
        };
        let manager = TaskManager::with_config(config);

        // Run task 1
        let res1 = manager.start_task("echo ttl_task_1").await.unwrap();
        let v1: serde_json::Value = serde_json::from_str(&res1).unwrap();
        let id1 = v1["task_id"].as_str().unwrap();

        // Wait for task 1 to finish
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Ok(st) = manager.check_status(id1).await {
                let rep: TaskStatusReport = serde_json::from_str(&st).unwrap();
                if rep.status == TaskStatus::Success {
                    break;
                }
            }
        }

        // Sleep 1.2s to exceed completed_ttl_secs (1s)
        tokio::time::sleep(Duration::from_millis(1200)).await;

        // Run task 2 (this will trigger cleanup_internal)
        let res2 = manager.start_task("echo ttl_task_2").await.unwrap();
        let v2: serde_json::Value = serde_json::from_str(&res2).unwrap();
        let id2 = v2["task_id"].as_str().unwrap();

        // Wait for task 2 to finish
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Ok(st) = manager.check_status(id2).await {
                let rep: TaskStatusReport = serde_json::from_str(&st).unwrap();
                if rep.status == TaskStatus::Success {
                    break;
                }
            }
        }

        // Task 1 should have been evicted by TTL cleanup!
        assert!(
            manager.check_status(id1).await.is_err(),
            "Task 1 should have been evicted by TTL cleanup"
        );
        // Task 2 should still be present
        assert!(manager.check_status(id2).await.is_ok());

        // Now test max_retained_tasks: max is 2.
        // Start task 3 and task 4.
        let res3 = manager.start_task("echo ttl_task_3").await.unwrap();
        let v3: serde_json::Value = serde_json::from_str(&res3).unwrap();
        let id3 = v3["task_id"].as_str().unwrap();

        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Ok(st) = manager.check_status(id3).await {
                let rep: TaskStatusReport = serde_json::from_str(&st).unwrap();
                if rep.status == TaskStatus::Success {
                    break;
                }
            }
        }

        let res4 = manager.start_task("echo ttl_task_4").await.unwrap();
        let v4: serde_json::Value = serde_json::from_str(&res4).unwrap();
        let id4 = v4["task_id"].as_str().unwrap();

        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Ok(st) = manager.check_status(id4).await {
                let rep: TaskStatusReport = serde_json::from_str(&st).unwrap();
                if rep.status == TaskStatus::Success {
                    break;
                }
            }
        }

        // Trigger explicit cleanup
        manager.cleanup_tasks().await;

        // With max_retained_tasks = 2, older completed task (id2) should be evicted, leaving 2 newest (id3, id4)
        assert!(manager.check_status(id2).await.is_err());
        assert!(manager.check_status(id3).await.is_ok());
        assert!(manager.check_status(id4).await.is_ok());
    }

    #[tokio::test]
    async fn test_task_process_tree_cancellation() {
        let manager = TaskManager::new();

        // Command that spawns a process tree
        let cmd = if cfg!(windows) {
            "cmd /C powershell -Command \"Start-Sleep -Seconds 10\""
        } else {
            "sh -c 'sleep 10'"
        };

        let start_res = manager.start_task(cmd).await.expect("Must start task");
        let v_start: serde_json::Value = serde_json::from_str(&start_res).unwrap();
        let task_id = v_start["task_id"].as_str().unwrap();

        let status_res = manager.check_status(task_id).await.unwrap();
        let report: TaskStatusReport = serde_json::from_str(&status_res).unwrap();
        assert_eq!(report.status, TaskStatus::Running);

        // Cancel task: terminates the entire process tree
        let cancel_res = manager.cancel_task(task_id).await.unwrap();
        assert!(cancel_res.contains("successfully cancelled"));

        let status_after = manager.check_status(task_id).await.unwrap();
        let report_after: TaskStatusReport = serde_json::from_str(&status_after).unwrap();
        assert_eq!(report_after.status, TaskStatus::Cancelled);

        let output = manager.get_output(task_id, None).await.unwrap();
        assert!(output.contains("Cancelled"));
    }

    #[tokio::test]
    async fn test_task_status_state_machine_and_race_protection() {
        assert!(TaskStatus::Running.can_transition_to(TaskStatus::Success));
        assert!(TaskStatus::Running.can_transition_to(TaskStatus::Failed));
        assert!(TaskStatus::Running.can_transition_to(TaskStatus::Cancelling));
        assert!(TaskStatus::Cancelling.can_transition_to(TaskStatus::Cancelled));

        // Invalid transitions strictly rejected
        assert!(!TaskStatus::Cancelling.can_transition_to(TaskStatus::Success));
        assert!(!TaskStatus::Cancelling.can_transition_to(TaskStatus::Failed));
        assert!(!TaskStatus::Cancelled.can_transition_to(TaskStatus::Success));
        assert!(!TaskStatus::Cancelled.can_transition_to(TaskStatus::Failed));
        assert!(!TaskStatus::Success.can_transition_to(TaskStatus::Running));
        assert!(!TaskStatus::Failed.can_transition_to(TaskStatus::Cancelled));

        // Verify BackgroundTaskInternal transition_to
        let mut internal = BackgroundTaskInternal {
            id: "test-race-id".to_string(),
            command: "echo test".to_string(),
            status: TaskStatus::Running,
            exit_code: None,
            start_time: chrono::Utc::now(),
            end_time: None,
            output_buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            cancel_sender: None,
        };

        // Transition Running -> Cancelling
        assert!(internal.transition_to(TaskStatus::Cancelling));
        assert_eq!(internal.status, TaskStatus::Cancelling);

        // Attempt worker race: worker tries to mark as Success or Failed
        assert!(!internal.transition_to(TaskStatus::Success));
        assert_eq!(internal.status, TaskStatus::Cancelling);

        assert!(!internal.transition_to(TaskStatus::Failed));
        assert_eq!(internal.status, TaskStatus::Cancelling);

        // Transition Cancelling -> Cancelled
        assert!(internal.transition_to(TaskStatus::Cancelled));
        assert_eq!(internal.status, TaskStatus::Cancelled);

        // Post-cancellation attempts cannot overwrite
        assert!(!internal.transition_to(TaskStatus::Success));
        assert_eq!(internal.status, TaskStatus::Cancelled);
    }
}
