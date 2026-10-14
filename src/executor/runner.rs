//! Command execution runner with bounded memory, concurrency, and timeout handling.

use crate::executor::logger::compress_output;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration limits for bounded command execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLimits {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub termination_grace: Duration,
}

impl Default for CommandLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_stdout_bytes: 1_048_576,
            max_stderr_bytes: 1_048_576,
            termination_grace: Duration::from_millis(2000),
        }
    }
}

impl CommandLimits {
    pub fn new(
        timeout: Duration,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
        termination_grace: Duration,
    ) -> Self {
        Self {
            timeout,
            max_stdout_bytes,
            max_stderr_bytes,
            termination_grace,
        }
    }
}

/// Outcome of bounded command execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutcome {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
}

impl CommandOutcome {
    /// Returns true if the command exited normally with exit code 0 and did not time out.
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }

    /// Lossy UTF-8 string representation of stdout.
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    /// Lossy UTF-8 string representation of stderr.
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }
}

#[derive(Default)]
struct StreamBuffer {
    data: Vec<u8>,
    truncated: bool,
}

/// Reads from an async stream concurrently into a memory-bounded accumulator.
///
/// Excess bytes beyond `max_bytes` are drained and discarded to prevent the
/// child process from blocking on full OS pipe buffers.
async fn read_stream_bounded<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    max_bytes: usize,
    shared: Arc<std::sync::Mutex<StreamBuffer>>,
) {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 8192];

    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break, // EOF reached
            Ok(n) => {
                if let Ok(mut guard) = shared.lock() {
                    let current_len = guard.data.len();
                    if current_len < max_bytes {
                        let available = max_bytes - current_len;
                        let to_take = n.min(available);
                        guard.data.extend_from_slice(&buf[..to_take]);
                        if n > to_take {
                            guard.truncated = true;
                        }
                    } else {
                        guard.truncated = true;
                    }
                }
            }
            Err(_) => break, // Pipe closed or broken
        }
    }
}

/// Gracefully terminate and reap a child process, with fallback to forced tree kill.
///
/// Guaranteed to invoke `child.wait()` to prevent zombie processes.
async fn terminate_process(mut child: tokio::process::Child, grace: Duration) -> Option<i32> {
    let pid = child.id();

    // On Unix: soft termination (SIGTERM) to process group (-pgid), wait grace, fallback to forced SIGKILL, then wait()
    #[cfg(unix)]
    {
        if let Some(pid_val) = pid {
            let pgid = pid_val as libc::pid_t;
            unsafe {
                libc::kill(-pgid, libc::SIGTERM);
            }
            match tokio::time::timeout(grace, child.wait()).await {
                Ok(Ok(status)) => status.code(),
                _ => {
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    let _ = child.kill().await;
                    child.wait().await.ok().and_then(|s| s.code())
                }
            }
        } else {
            let _ = child.kill().await;
            child.wait().await.ok().and_then(|s| s.code())
        }
    }

    // On Windows: kill entire process tree (/T /F) to prevent orphaned subprocesses
    #[cfg(windows)]
    {
        let _ = grace; // used on Unix for SIGTERM grace
        if let Some(pid_val) = pid {
            let mut kill_cmd = tokio::process::Command::new("taskkill");
            kill_cmd.args(["/PID", &pid_val.to_string(), "/T", "/F"]);
            kill_cmd.stdout(std::process::Stdio::null());
            kill_cmd.stderr(std::process::Stdio::null());

            // Await taskkill with a strict timeout to prevent blocking the async runtime
            let _ = tokio::time::timeout(Duration::from_millis(1500), async {
                if let Ok(mut kill_child) = kill_cmd.spawn() {
                    let _ = kill_child.wait().await;
                }
            })
            .await;
        }
        let _ = child.kill().await;
        child.wait().await.ok().and_then(|s| s.code())
    }
}

/// Executes a `tokio::process::Command` under strict resource bounds:
/// memory limits on stdout/stderr, async concurrent reading, and safe termination.
pub async fn execute_process_bounded(
    mut process_cmd: tokio::process::Command,
    limits: &CommandLimits,
) -> Result<CommandOutcome, String> {
    #[cfg(unix)]
    {
        process_cmd.process_group(0);
    }

    process_cmd.stdout(std::process::Stdio::piped());
    process_cmd.stderr(std::process::Stdio::piped());

    let mut child = process_cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn process: {e}"))?;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_acc = Arc::new(std::sync::Mutex::new(StreamBuffer::default()));
    let stderr_acc = Arc::new(std::sync::Mutex::new(StreamBuffer::default()));

    let stdout_task = if let Some(stdout) = stdout_pipe {
        tokio::spawn(read_stream_bounded(
            stdout,
            limits.max_stdout_bytes,
            stdout_acc.clone(),
        ))
    } else {
        tokio::spawn(async {})
    };

    let stderr_task = if let Some(stderr) = stderr_pipe {
        tokio::spawn(read_stream_bounded(
            stderr,
            limits.max_stderr_bytes,
            stderr_acc.clone(),
        ))
    } else {
        tokio::spawn(async {})
    };

    let (exit_code, timed_out) = tokio::select! {
        status_res = child.wait() => {
            match status_res {
                Ok(status) => {
                    let _ = tokio::time::timeout(limits.termination_grace, async {
                        let _ = stdout_task.await;
                        let _ = stderr_task.await;
                    }).await;
                    (status.code(), false)
                }
                Err(e) => return Err(format!("Process wait failed: {e}")),
            }
        }
        _ = tokio::time::sleep(limits.timeout) => {
            stdout_task.abort();
            stderr_task.abort();
            let code = terminate_process(child, limits.termination_grace).await;
            (code, true)
        }
    };

    let (stdout, stdout_truncated) = {
        let mut guard = stdout_acc.lock().map_err(|e| format!("Lock error: {e}"))?;
        (std::mem::take(&mut guard.data), guard.truncated)
    };

    let (stderr, stderr_truncated) = {
        let mut guard = stderr_acc.lock().map_err(|e| format!("Lock error: {e}"))?;
        (std::mem::take(&mut guard.data), guard.truncated)
    };

    Ok(CommandOutcome {
        exit_code,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        timed_out,
    })
}

/// Executes a shell command string with bounded limits.
pub async fn execute_command_bounded(
    command_str: &str,
    limits: &CommandLimits,
) -> Result<CommandOutcome, String> {
    let process_cmd = if cfg!(windows) {
        let mut c = tokio::process::Command::new("cmd");
        c.args(["/C", command_str]);
        c
    } else {
        let mut c = tokio::process::Command::new("sh");
        c.args(["-c", command_str]);
        c
    };

    execute_process_bounded(process_cmd, limits).await
}

/// Helper to execute a command process with a quick timeout and bounded output,
/// returning Some(stdout) on success (exit code 0), or None otherwise.
pub async fn execute_quick_process(
    cmd: tokio::process::Command,
    timeout_secs: u64,
) -> Option<String> {
    let limits = CommandLimits {
        timeout: Duration::from_secs(timeout_secs),
        max_stdout_bytes: 512 * 1024,
        max_stderr_bytes: 64 * 1024,
        termination_grace: Duration::from_millis(500),
    };
    if let Ok(outcome) = execute_process_bounded(cmd, &limits).await
        && outcome.success()
    {
        return Some(outcome.stdout_lossy());
    }
    None
}

/// Executes a direct process command without shell wrapping, enforcing bounded limits
/// and returning compressed smart logs.
pub async fn execute_process_with_smart_logs_bounded(
    cmd: tokio::process::Command,
    limits: &CommandLimits,
) -> Result<String, String> {
    let start = Instant::now();
    let outcome = execute_process_bounded(cmd, limits).await?;
    let elapsed = start.elapsed().as_secs_f64();

    if outcome.timed_out {
        let mut err_msg = format!(
            "FAILED: Execution timed out after {:.0} seconds",
            limits.timeout.as_secs_f64()
        );
        if !outcome.stdout.is_empty() || !outcome.stderr.is_empty() {
            let stdout = outcome.stdout_lossy();
            let stderr = outcome.stderr_lossy();
            let compressed = compress_output(outcome.exit_code, elapsed, &stdout, &stderr);
            err_msg.push_str(&format!("\nOutput captured before timeout:\n{compressed}"));
        }
        return Err(err_msg);
    }

    let mut stdout = outcome.stdout_lossy();
    if outcome.stdout_truncated {
        stdout.push_str(&format!(
            "\n[stdout truncated: exceeded max limit of {} bytes]",
            limits.max_stdout_bytes
        ));
    }

    let mut stderr = outcome.stderr_lossy();
    if outcome.stderr_truncated {
        stderr.push_str(&format!(
            "\n[stderr truncated: exceeded max limit of {} bytes]",
            limits.max_stderr_bytes
        ));
    }

    let compressed = compress_output(outcome.exit_code, elapsed, &stdout, &stderr);

    if outcome.success() {
        Ok(compressed)
    } else {
        Err(compressed)
    }
}

/// Executes a direct process command without shell wrapping, using default 1MB buffer limits
/// and the specified timeout duration.
pub async fn execute_process_with_smart_logs(
    cmd: tokio::process::Command,
    timeout_duration: Duration,
) -> Result<String, String> {
    let limits = CommandLimits {
        timeout: timeout_duration,
        max_stdout_bytes: 1_048_576,
        max_stderr_bytes: 1_048_576,
        termination_grace: Duration::from_millis(2000),
    };
    execute_process_with_smart_logs_bounded(cmd, &limits).await
}

/// Executes a shell command with bounded limits and returns compressed smart logs.
pub async fn execute_command_with_smart_logs_bounded(
    command_str: &str,
    limits: &CommandLimits,
) -> Result<String, String> {
    let process_cmd = if cfg!(windows) {
        let mut c = tokio::process::Command::new("cmd");
        c.args(["/C", command_str]);
        c
    } else {
        let mut c = tokio::process::Command::new("sh");
        c.args(["-c", command_str]);
        c
    };

    execute_process_with_smart_logs_bounded(process_cmd, limits).await
}

/// Safely spawn and execute a shell command, capturing output up to default bounded limits
/// and applying smart log compression.
///
/// Returns `Ok(compressed_output)` on success (exit code 0), or `Err(compressed_error)` on failure or timeout.
pub async fn execute_command_with_smart_logs(
    command_str: &str,
    timeout_duration: Duration,
) -> Result<String, String> {
    let limits = CommandLimits {
        timeout: timeout_duration,
        max_stdout_bytes: 1_048_576,
        max_stderr_bytes: 1_048_576,
        termination_grace: Duration::from_millis(2000),
    };
    execute_command_with_smart_logs_bounded(command_str, &limits).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_base64(bytes: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
            let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(TABLE[(triple >> 18) & 0x3F] as char);
            out.push(TABLE[(triple >> 12) & 0x3F] as char);
            if chunk.len() > 1 {
                out.push(TABLE[(triple >> 6) & 0x3F] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(TABLE[triple & 0x3F] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    fn ps_cmd(script: &str) -> String {
        let utf16: Vec<u8> = script
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        format!(
            "powershell -NoProfile -NonInteractive -EncodedCommand {}",
            to_base64(&utf16)
        )
    }

    #[tokio::test]
    async fn test_execute_command_success() {
        let result =
            execute_command_with_smart_logs("echo runner_test_ok", Duration::from_secs(5)).await;
        assert!(result.is_ok());
        let text = result.unwrap();
        assert!(text.contains("SUCCESS: Command completed in"));
        assert!(text.contains("runner_test_ok"));
    }

    #[tokio::test]
    async fn test_execute_command_failure() {
        // Run a command guaranteed to fail
        let result = execute_command_with_smart_logs(
            "dir /invalid_path_does_not_exist_xyz",
            Duration::from_secs(5),
        )
        .await;
        assert!(result.is_err());
        let text = result.unwrap_err();
        assert!(text.contains("FAILED: Command exited with code"));
    }

    #[tokio::test]
    async fn test_bounded_output_truncation_stdout() {
        // Generate 50KB of stdout with max limit 2048 bytes
        let cmd = if cfg!(windows) {
            ps_cmd("[Console]::Out.Write('X' * 50000)")
        } else {
            "head -c 50000 /dev/zero | tr '\\0' 'X'".to_string()
        };

        let limits = CommandLimits {
            timeout: Duration::from_secs(10),
            max_stdout_bytes: 2048,
            max_stderr_bytes: 2048,
            termination_grace: Duration::from_millis(1000),
        };

        let outcome = execute_command_bounded(&cmd, &limits)
            .await
            .expect("Execution should succeed");
        assert_eq!(
            outcome.stdout.len(),
            2048,
            "Buffered stdout must strictly equal max_stdout_bytes"
        );
        assert!(outcome.stdout_truncated, "stdout_truncated must be true");
        assert!(!outcome.timed_out, "Command should finish within timeout");
    }

    #[tokio::test]
    async fn test_bounded_output_truncation_stderr() {
        // Generate 40KB of stderr with max limit 1024 bytes
        let cmd = if cfg!(windows) {
            ps_cmd("[Console]::Error.Write('E' * 40000)")
        } else {
            "sh -c \"head -c 40000 /dev/zero | tr '\\0' 'E' >&2\"".to_string()
        };

        let limits = CommandLimits {
            timeout: Duration::from_secs(10),
            max_stdout_bytes: 4096,
            max_stderr_bytes: 1024,
            termination_grace: Duration::from_millis(1000),
        };

        let outcome = execute_command_bounded(&cmd, &limits)
            .await
            .expect("Execution should succeed");
        assert_eq!(
            outcome.stderr.len(),
            1024,
            "Buffered stderr must strictly equal max_stderr_bytes"
        );
        assert!(outcome.stderr_truncated, "stderr_truncated must be true");
        assert!(!outcome.timed_out);
    }

    #[tokio::test]
    async fn test_simultaneous_stdout_and_stderr() {
        // Output simultaneously to both stdout and stderr
        let cmd = if cfg!(windows) {
            ps_cmd("[Console]::Out.Write('STDOUT_PART'); [Console]::Error.Write('STDERR_PART')")
        } else {
            "sh -c \"printf 'STDOUT_PART'; printf 'STDERR_PART' >&2\"".to_string()
        };

        let limits = CommandLimits {
            timeout: Duration::from_secs(10),
            max_stdout_bytes: 1024,
            max_stderr_bytes: 1024,
            termination_grace: Duration::from_millis(1000),
        };

        let outcome = execute_command_bounded(&cmd, &limits)
            .await
            .expect("Execution should succeed");
        assert!(outcome.stdout_lossy().contains("STDOUT_PART"));
        assert!(outcome.stderr_lossy().contains("STDERR_PART"));
        assert!(!outcome.stdout_truncated);
        assert!(!outcome.stderr_truncated);
        assert!(!outcome.timed_out);
    }

    #[tokio::test]
    async fn test_timeout_and_process_cleanup_infinite_loop() {
        // Command that runs for a long time
        let cmd = if cfg!(windows) {
            ps_cmd("while ($true) { Start-Sleep -Milliseconds 100 }")
        } else {
            "while true; do sleep 0.1; done".to_string()
        };

        let limits = CommandLimits {
            timeout: Duration::from_millis(500),
            max_stdout_bytes: 1024,
            max_stderr_bytes: 1024,
            termination_grace: Duration::from_millis(500),
        };

        let outcome = execute_command_bounded(&cmd, &limits)
            .await
            .expect("Execution should return outcome");
        assert!(outcome.timed_out, "Outcome must indicate timeout");
        // Check that smart logs also reports timeout error
        let smart_res = execute_command_with_smart_logs_bounded(&cmd, &limits).await;
        assert!(smart_res.is_err());
        assert!(smart_res.unwrap_err().contains("Execution timed out"));
    }

    #[tokio::test]
    async fn test_large_volume_does_not_exceed_limit_and_memory() {
        // Generate 10 MB of stdout with 64KB memory limit
        let cmd = if cfg!(windows) {
            ps_cmd("[Console]::Out.Write('A' * 10000000)")
        } else {
            "head -c 10000000 /dev/zero | tr '\\0' 'A'".to_string()
        };

        let limits = CommandLimits {
            timeout: Duration::from_secs(15),
            max_stdout_bytes: 65536,
            max_stderr_bytes: 65536,
            termination_grace: Duration::from_millis(1000),
        };

        let outcome = execute_command_bounded(&cmd, &limits)
            .await
            .expect("Execution succeeds");
        assert_eq!(outcome.stdout.len(), 65536);
        assert!(outcome.stdout_truncated);
        assert!(!outcome.timed_out);
    }

    #[tokio::test]
    async fn test_non_zero_exit_code_captured() {
        let cmd = if cfg!(windows) {
            "cmd /C exit 42"
        } else {
            "sh -c 'exit 42'"
        };

        let limits = CommandLimits {
            timeout: Duration::from_secs(5),
            max_stdout_bytes: 1024,
            max_stderr_bytes: 1024,
            termination_grace: Duration::from_millis(500),
        };

        let outcome = execute_command_bounded(cmd, &limits)
            .await
            .expect("Execution succeeds");
        assert_eq!(outcome.exit_code, Some(42));
        assert!(!outcome.success());
    }
}
