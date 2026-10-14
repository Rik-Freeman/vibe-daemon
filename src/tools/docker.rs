//! Docker & Podman Container Management subsystem.
//! Provides AI models with structured tools for container monitoring, log retrieval
//! with Smart Log Engine compression, safe restarts, and docker-compose orchestration.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

use crate::config::SecurityConfig;
use crate::executor::{compress_container_logs, execute_process_with_smart_logs};
use crate::guard::firewall::{check_command_safety_with_config, check_container_identifier_safety};
use crate::guard::fs_guard::{check_file_write_safety_with_config, normalize_path};

/// Structured representation of a container returned by `docker_ps`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerInfo {
    pub id: String,
    pub names: Vec<String>,
    pub image: String,
    pub status: String,
    pub state: String,
    pub ports: String,
    pub created: String,
}

/// Structured real-time container metrics returned by `docker_stats`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerStats {
    pub id: String,
    pub name: String,
    pub cpu_perc: String,
    pub mem_usage: String,
    pub mem_perc: String,
    pub net_io: String,
    pub block_io: String,
    pub pids: String,
}

// -----------------------------------------------------------------------------
// Helper Extraction & Parsing
// -----------------------------------------------------------------------------

fn get_string_field(v: &Value, keys: &[&str]) -> Option<String> {
    for &key in keys {
        if let Some(val) = v.get(key) {
            if let Some(s) = val.as_str() {
                return Some(s.to_string());
            } else if !val.is_null() && !val.is_object() && !val.is_array() {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn get_field<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    for &key in keys {
        if let Some(val) = v.get(key) {
            return Some(val);
        }
    }
    None
}

fn value_to_container_info(v: &Value) -> Option<ContainerInfo> {
    if !v.is_object() {
        return None;
    }

    let id = get_string_field(v, &["ID", "Id", "id", "Container"]).unwrap_or_default();

    let names = if let Some(arr) = get_field(v, &["Names", "names"]).and_then(|val| val.as_array())
    {
        arr.iter()
            .filter_map(|item| item.as_str().map(|s| s.trim_start_matches('/').to_string()))
            .collect()
    } else if let Some(s) = get_string_field(v, &["Names", "names", "Name", "name"]) {
        s.split(',')
            .map(|part| part.trim().trim_start_matches('/').to_string())
            .filter(|p| !p.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    let image = get_string_field(v, &["Image", "image"]).unwrap_or_default();
    let status = get_string_field(v, &["Status", "status"]).unwrap_or_default();
    let state = get_string_field(v, &["State", "state"]).unwrap_or_else(|| {
        let lower = status.to_lowercase();
        if lower.starts_with("up") {
            "running".to_string()
        } else if lower.starts_with("exited") {
            "exited".to_string()
        } else {
            status.clone()
        }
    });

    let ports = if let Some(p_str) = get_string_field(v, &["Ports", "ports"]) {
        p_str
    } else if let Some(arr) = get_field(v, &["Ports", "ports"]).and_then(|val| val.as_array()) {
        let port_strings: Vec<String> = arr
            .iter()
            .map(|item| {
                if let Some(s) = item.as_str() {
                    s.to_string()
                } else {
                    item.to_string()
                }
            })
            .collect();
        port_strings.join(", ")
    } else {
        String::new()
    };

    let created = get_string_field(
        v,
        &[
            "CreatedAt",
            "created_at",
            "Created",
            "created",
            "RunningFor",
        ],
    )
    .unwrap_or_default();

    Some(ContainerInfo {
        id,
        names,
        image,
        status,
        state,
        ports,
        created,
    })
}

fn value_to_container_stats(v: &Value) -> Option<ContainerStats> {
    if !v.is_object() {
        return None;
    }

    let id = get_string_field(v, &["ID", "Id", "id", "Container"]).unwrap_or_default();
    let name = get_string_field(v, &["Name", "name", "Names", "names"])
        .map(|s| s.trim_start_matches('/').to_string())
        .unwrap_or_default();
    let cpu_perc = get_string_field(v, &["CPUPerc", "cpu_perc", "CPU", "cpu"]).unwrap_or_default();
    let mem_usage =
        get_string_field(v, &["MemUsage", "mem_usage", "Memory", "memory"]).unwrap_or_default();
    let mem_perc = get_string_field(v, &["MemPerc", "mem_perc"]).unwrap_or_default();
    let net_io = get_string_field(v, &["NetIO", "net_io"]).unwrap_or_default();
    let block_io = get_string_field(v, &["BlockIO", "block_io"]).unwrap_or_default();
    let pids = get_string_field(v, &["PIDs", "pids"]).unwrap_or_default();

    Some(ContainerStats {
        id,
        name,
        cpu_perc,
        mem_usage,
        mem_perc,
        net_io,
        block_io,
        pids,
    })
}

/// Parses output of `docker ps --format json` (both newline-delimited JSON and JSON array).
pub fn parse_docker_ps_json(raw: &str) -> Vec<ContainerInfo> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // 1. Line-by-line NDJSON format
    let mut results = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(line)
            && let Some(info) = value_to_container_info(&val)
        {
            results.push(info);
        }
    }

    if !results.is_empty() {
        return results;
    }

    // 2. Fallback: single JSON array
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(trimmed) {
        for item in items {
            if let Some(info) = value_to_container_info(&item) {
                results.push(info);
            }
        }
    }

    results
}

/// Parses output of `docker stats --no-stream --format json` (NDJSON and JSON array).
pub fn parse_docker_stats_json(raw: &str) -> Vec<ContainerStats> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // 1. Line-by-line NDJSON format
    let mut results = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(line)
            && let Some(stats) = value_to_container_stats(&val)
        {
            results.push(stats);
        }
    }

    if !results.is_empty() {
        return results;
    }

    // 2. Fallback: single JSON array
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(trimmed) {
        for item in items {
            if let Some(stats) = value_to_container_stats(&item) {
                results.push(stats);
            }
        }
    }

    results
}

// -----------------------------------------------------------------------------
// Daemon Detection & Error Diagnostics
// -----------------------------------------------------------------------------

/// Classifies raw Docker command errors into intelligible, user-friendly diagnostic messages.
pub fn classify_docker_error(raw_err: &str) -> String {
    let lower = raw_err.to_lowercase();
    if lower.contains("not recognized")
        || lower.contains("command not found")
        || (lower.contains("no such file or directory") && lower.contains("docker"))
    {
        "Docker is not installed or not available in the system PATH. Please ensure Docker or Podman is installed.".to_string()
    } else if lower.contains("failed to connect to the docker api")
        || lower.contains("cannot connect to the docker daemon")
        || lower.contains("is the docker daemon running")
        || lower.contains("error during connect")
        || lower.contains("dockerdesktoplinuxengine")
        || lower.contains("docker_engine")
        || lower.contains("connection refused")
        || lower.contains("daemon is not running")
        || lower.contains("failed to connect to docker")
        || lower.contains("permission denied")
    {
        "Docker daemon is not reachable: verify that Docker is installed and the Docker daemon service is running (e.g. 'systemctl start docker' or start Docker Desktop).".to_string()
    } else {
        format!("Docker command failed: {raw_err}")
    }
}

/// Checks whether Docker daemon is active and responsive.
pub async fn check_docker_available() -> Result<(), String> {
    let mut cmd = tokio::process::Command::new("docker");
    cmd.args(["info", "--format", "{{json .ServerVersion}}"]);

    let res = execute_process_with_smart_logs(cmd, Duration::from_secs(5)).await;

    match res {
        Ok(out) => {
            let lower = out.to_lowercase();
            if lower.contains("error during connect")
                || lower.contains("cannot connect")
                || lower.contains("dockerdesktoplinuxengine")
                || lower.contains("daemon is not running")
            {
                Err(classify_docker_error(&out))
            } else {
                Ok(())
            }
        }
        Err(err) => Err(classify_docker_error(&err)),
    }
}

// -----------------------------------------------------------------------------
// Container Operations
// -----------------------------------------------------------------------------

/// Lists active or all containers with status, ports, image, and IDs.
pub async fn docker_ps(all: bool) -> Result<String, String> {
    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("ps");
    if all {
        cmd.arg("-a");
    }
    cmd.args(["--format", "json"]);

    let res = execute_process_with_smart_logs(cmd, Duration::from_secs(10)).await;
    match res {
        Ok(out) => {
            let containers = parse_docker_ps_json(&out);
            if containers.is_empty() {
                if all {
                    Ok("No containers found in system.".to_string())
                } else {
                    Ok("No active containers found.".to_string())
                }
            } else {
                serde_json::to_string_pretty(&containers)
                    .map_err(|e| format!("Failed to format containers: {e}"))
            }
        }
        Err(err) => Err(classify_docker_error(&err)),
    }
}

/// Retrieves container logs compressed via Smart Log Engine.
pub async fn docker_logs(
    container_name_or_id: &str,
    tail: Option<usize>,
) -> Result<String, String> {
    let default_sec = SecurityConfig::default();
    docker_logs_with_config(container_name_or_id, tail, &default_sec).await
}

/// Retrieves container logs with explicit SecurityConfig.
pub async fn docker_logs_with_config(
    container_name_or_id: &str,
    tail: Option<usize>,
    security: &SecurityConfig,
) -> Result<String, String> {
    let trimmed = container_name_or_id.trim();
    check_container_identifier_safety(trimmed).map_err(|e| format!("Security Violation: {e}"))?;

    let tail_lines = tail.unwrap_or(100).clamp(1, 5000);
    let cmd_str = format!("docker logs --tail {tail_lines} {trimmed}");
    check_command_safety_with_config(&cmd_str, security)
        .map_err(|e| format!("Security Violation: {e}"))?;

    let mut cmd = tokio::process::Command::new("docker");
    let tail_str = tail_lines.to_string();
    cmd.args(["logs", "--tail", &tail_str, trimmed]);

    let res = execute_process_with_smart_logs(cmd, Duration::from_secs(15)).await;
    match res {
        Ok(raw_output) => Ok(compress_container_logs(&raw_output, trimmed)),
        Err(err) => Err(classify_docker_error(&err)),
    }
}

/// Safely restarts a container by name or ID.
pub async fn docker_restart(container_name_or_id: &str) -> Result<String, String> {
    let default_sec = SecurityConfig::default();
    docker_restart_with_config(container_name_or_id, &default_sec).await
}

/// Safely restarts a container by name or ID with explicit SecurityConfig.
pub async fn docker_restart_with_config(
    container_name_or_id: &str,
    security: &SecurityConfig,
) -> Result<String, String> {
    let trimmed = container_name_or_id.trim();
    check_container_identifier_safety(trimmed).map_err(|e| format!("Security Violation: {e}"))?;

    let cmd_str = format!("docker restart {trimmed}");
    check_command_safety_with_config(&cmd_str, security)
        .map_err(|e| format!("Security Violation: {e}"))?;

    let mut cmd = tokio::process::Command::new("docker");
    cmd.args(["restart", trimmed]);

    let res = execute_process_with_smart_logs(cmd, Duration::from_secs(30)).await;
    match res {
        Ok(out) => {
            let details = out.trim();
            if details.is_empty() {
                Ok(format!("Container '{trimmed}' restarted successfully."))
            } else {
                Ok(format!(
                    "Container '{trimmed}' restarted successfully: {details}"
                ))
            }
        }
        Err(err) => Err(classify_docker_error(&err)),
    }
}

/// Launches or updates a compose stack in detached mode with default SecurityConfig.
pub async fn docker_compose_up(
    file_path: Option<&str>,
    service_name: Option<&str>,
) -> Result<String, String> {
    let default_sec = SecurityConfig::default();
    docker_compose_up_with_config(file_path, service_name, &default_sec).await
}

/// Launches or updates a compose stack in detached mode with path Guard verification.
pub async fn docker_compose_up_with_config(
    file_path: Option<&str>,
    service_name: Option<&str>,
    security: &SecurityConfig,
) -> Result<String, String> {
    // 1. Validate file_path if provided
    let mut clean_file_path: Option<String> = None;
    if let Some(fp) = file_path {
        let trimmed_fp = fp.trim();
        if trimmed_fp.is_empty() {
            return Err("Compose file path cannot be empty".to_string());
        }

        let path = Path::new(trimmed_fp);
        let normalized = normalize_path(path).map_err(|e| format!("Security Violation: {e}"))?;

        check_file_write_safety_with_config(&normalized, security)
            .map_err(|e| format!("Security Violation: {e}"))?;

        let file_name_lower = normalized
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        if !file_name_lower.ends_with(".yml") && !file_name_lower.ends_with(".yaml") {
            return Err(format!(
                "Invalid compose file '{trimmed_fp}': expected a YAML configuration file (.yml or .yaml)"
            ));
        }

        let clean_path = normalized.to_string_lossy().replace('\\', "/");
        clean_file_path = Some(clean_path);
    }

    // 2. Validate service_name if provided
    let mut clean_service: Option<String> = None;
    if let Some(svc) = service_name {
        let trimmed_svc = svc.trim();
        if trimmed_svc.is_empty() {
            return Err("Service name cannot be empty when specified".to_string());
        }
        if !trimmed_svc
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(format!(
                "Invalid characters in service name '{trimmed_svc}': service name must contain only alphanumeric characters, '.', '-', or '_'"
            ));
        }
        clean_service = Some(trimmed_svc.to_string());
    }

    // 3. Verify firewall guard safety
    let compose_file_arg = clean_file_path
        .as_ref()
        .map(|p| format!("-f \"{p}\" "))
        .unwrap_or_default();
    let service_arg = clean_service
        .as_ref()
        .map(|s| format!(" {s}"))
        .unwrap_or_default();
    let cmd_str = format!("docker compose {compose_file_arg}up -d{service_arg}");
    check_command_safety_with_config(&cmd_str, security)
        .map_err(|e| format!("Security Violation: {e}"))?;

    // 4. Execute with structured process arguments (no shell interpolation)
    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("compose");
    if let Some(ref p) = clean_file_path {
        cmd.args(["-f", p]);
    }
    cmd.args(["up", "-d"]);
    if let Some(ref s) = clean_service {
        cmd.arg(s);
    }

    let res = execute_process_with_smart_logs(cmd, Duration::from_secs(60)).await;
    match res {
        Ok(output) => Ok(output),
        Err(err) => Err(classify_docker_error(&err)),
    }
}

/// Gathers real-time CPU, RAM, network, and I/O metrics for all running containers.
pub async fn docker_stats() -> Result<String, String> {
    let mut cmd = tokio::process::Command::new("docker");
    cmd.args(["stats", "--no-stream", "--format", "json"]);

    let res = execute_process_with_smart_logs(cmd, Duration::from_secs(10)).await;
    match res {
        Ok(out) => {
            let stats = parse_docker_stats_json(&out);
            if stats.is_empty() {
                Ok("No running containers found to collect stats.".to_string())
            } else {
                serde_json::to_string_pretty(&stats)
                    .map_err(|e| format!("Failed to format container stats: {e}"))
            }
        }
        Err(err) => Err(classify_docker_error(&err)),
    }
}

// -----------------------------------------------------------------------------
// McpTool Implementations
// -----------------------------------------------------------------------------

use crate::mcp::protocol::CallToolResult;
use crate::tools::registry::{McpTool, ToolContext, ToolRegistry};
use async_trait::async_trait;

pub struct DockerPsTool;

#[async_trait]
impl McpTool for DockerPsTool {
    fn name(&self) -> &str {
        "docker_ps"
    }

    fn description(&self) -> &str {
        "Lists active or all containers with status, ports, image and IDs using structured Docker inspection."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "all": {
                    "type": "boolean",
                    "description": "Optional flag to show all containers including stopped ones (defaults to false)."
                }
            },
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let all_arg = args.get("all").and_then(|a| a.as_bool()).unwrap_or(false);

        match docker_ps(all_arg).await {
            Ok(res) => Ok(CallToolResult::text(res)),
            Err(e) => Ok(CallToolResult::error(e)),
        }
    }
}

pub struct DockerLogsTool;

#[async_trait]
impl McpTool for DockerLogsTool {
    fn name(&self) -> &str {
        "docker_logs"
    }

    fn description(&self) -> &str {
        "Retrieves container logs compressed via Smart Log Engine to protect context windows from log flooding."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "container_name_or_id": {
                    "type": "string",
                    "description": "Name or ID of the Docker container."
                },
                "tail": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5000,
                    "description": "Optional number of recent log lines to retrieve (defaults to 100)."
                }
            },
            "required": ["container_name_or_id"],
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let container_arg = args.get("container_name_or_id").and_then(|c| c.as_str());

        let tail_arg = args
            .get("tail")
            .and_then(|t| t.as_u64())
            .map(|t| t as usize);

        match container_arg {
            Some(cid) => match docker_logs_with_config(cid, tail_arg, &ctx.config.security).await {
                Ok(logs) => Ok(CallToolResult::text(logs)),
                Err(e) => Ok(CallToolResult::error(e)),
            },
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'container_name_or_id' must be a string",
            )),
        }
    }
}

pub struct DockerRestartTool;

#[async_trait]
impl McpTool for DockerRestartTool {
    fn name(&self) -> &str {
        "docker_restart"
    }

    fn description(&self) -> &str {
        "Safely restarts a Docker container by name or ID."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "container_name_or_id": {
                    "type": "string",
                    "description": "Name or ID of the Docker container to restart."
                }
            },
            "required": ["container_name_or_id"],
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let container_arg = args.get("container_name_or_id").and_then(|c| c.as_str());

        match container_arg {
            Some(cid) => match docker_restart_with_config(cid, &ctx.config.security).await {
                Ok(res) => Ok(CallToolResult::text(res)),
                Err(e) => Ok(CallToolResult::error(e)),
            },
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'container_name_or_id' must be a string",
            )),
        }
    }
}

pub struct DockerComposeUpTool;

#[async_trait]
impl McpTool for DockerComposeUpTool {
    fn name(&self) -> &str {
        "docker_compose_up"
    }

    fn description(&self) -> &str {
        "Launches or updates a Docker Compose stack in detached mode (-d) with path validation and execution timeout."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Optional path to the docker-compose.yml file (validated by security guard)."
                },
                "service_name": {
                    "type": "string",
                    "description": "Optional specific service name within the compose stack to start or update."
                }
            },
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let file_path_arg = args.get("file_path").and_then(|f| f.as_str());
        let service_name_arg = args.get("service_name").and_then(|s| s.as_str());

        match docker_compose_up_with_config(file_path_arg, service_name_arg, &ctx.config.security)
            .await
        {
            Ok(res) => Ok(CallToolResult::text(res)),
            Err(e) => Ok(CallToolResult::error(e)),
        }
    }
}

pub struct DockerStatsTool;

#[async_trait]
impl McpTool for DockerStatsTool {
    fn name(&self) -> &str {
        "docker_stats"
    }

    fn description(&self) -> &str {
        "Gathers real-time CPU, RAM, network, and I/O metrics for all running containers."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        _args: serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        match docker_stats().await {
            Ok(res) => Ok(CallToolResult::text(res)),
            Err(e) => Ok(CallToolResult::error(e)),
        }
    }
}

/// Registers the 5 Docker container management tools into the given registry.
pub fn register_docker_tools(registry: &mut ToolRegistry) {
    registry.register_tool(DockerPsTool);
    registry.register_tool(DockerLogsTool);
    registry.register_tool(DockerRestartTool);
    registry.register_tool(DockerComposeUpTool);
    registry.register_tool(DockerStatsTool);
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_docker_ps_ndjson() {
        let sample = r#"{"ID":"1a2b3c4d5e6f","Names":"web-frontend","Image":"nginx:alpine","Status":"Up 2 hours","State":"running","Ports":"0.0.0.0:80->80/tcp","CreatedAt":"2026-10-14 00:00:00"}
{"ID":"7g8h9i0j1k2l","Names":"db-postgres","Image":"postgres:15","Status":"Up 5 hours","State":"running","Ports":"5432/tcp","CreatedAt":"2026-10-13 21:00:00"}"#;

        let parsed = parse_docker_ps_json(sample);
        assert_eq!(parsed.len(), 2);

        assert_eq!(parsed[0].id, "1a2b3c4d5e6f");
        assert_eq!(parsed[0].names, vec!["web-frontend"]);
        assert_eq!(parsed[0].image, "nginx:alpine");
        assert_eq!(parsed[0].status, "Up 2 hours");
        assert_eq!(parsed[0].state, "running");
        assert_eq!(parsed[0].ports, "0.0.0.0:80->80/tcp");

        assert_eq!(parsed[1].id, "7g8h9i0j1k2l");
        assert_eq!(parsed[1].names, vec!["db-postgres"]);
        assert_eq!(parsed[1].image, "postgres:15");
        assert_eq!(parsed[1].status, "Up 5 hours");
        assert_eq!(parsed[1].state, "running");
        assert_eq!(parsed[1].ports, "5432/tcp");
    }

    #[test]
    fn test_parse_docker_ps_json_array() {
        let sample = r#"[
            {
                "Id": "abc123456789",
                "Names": ["/redis-cache"],
                "Image": "redis:7",
                "Status": "Exited (0) 10 minutes ago",
                "Ports": []
            }
        ]"#;

        let parsed = parse_docker_ps_json(sample);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "abc123456789");
        assert_eq!(parsed[0].names, vec!["redis-cache"]);
        assert_eq!(parsed[0].image, "redis:7");
        assert_eq!(parsed[0].status, "Exited (0) 10 minutes ago");
        assert_eq!(parsed[0].state, "exited");
    }

    #[test]
    fn test_parse_docker_ps_empty() {
        let parsed = parse_docker_ps_json("");
        assert!(parsed.is_empty());

        let parsed2 = parse_docker_ps_json("   \n  \n");
        assert!(parsed2.is_empty());
    }

    #[test]
    fn test_parse_docker_stats_ndjson() {
        let sample = r#"{"BlockIO":"0B / 0B","CPUPerc":"0.15%","Container":"1a2b3c4d","ID":"1a2b3c4d","MemPerc":"1.25%","MemUsage":"45.2MiB / 3.84GiB","Name":"nginx-proxy","NetIO":"1.2kB / 500B","PIDs":"3"}
{"BlockIO":"12MB / 4MB","CPUPerc":"1.82%","Container":"5e6f7g8h","ID":"5e6f7g8h","MemPerc":"5.40%","MemUsage":"212MiB / 3.84GiB","Name":"postgres-db","NetIO":"45MB / 12MB","PIDs":"12"}"#;

        let stats = parse_docker_stats_json(sample);
        assert_eq!(stats.len(), 2);

        assert_eq!(stats[0].id, "1a2b3c4d");
        assert_eq!(stats[0].name, "nginx-proxy");
        assert_eq!(stats[0].cpu_perc, "0.15%");
        assert_eq!(stats[0].mem_usage, "45.2MiB / 3.84GiB");
        assert_eq!(stats[0].mem_perc, "1.25%");
        assert_eq!(stats[0].net_io, "1.2kB / 500B");
        assert_eq!(stats[0].block_io, "0B / 0B");
        assert_eq!(stats[0].pids, "3");

        assert_eq!(stats[1].name, "postgres-db");
        assert_eq!(stats[1].pids, "12");
    }

    #[test]
    fn test_parse_docker_stats_json_array() {
        let sample = r#"[
            {
                "ID": "c100",
                "Name": "/app",
                "CPUPerc": "2.5%",
                "MemUsage": "100MB / 1GB",
                "MemPerc": "10.0%",
                "NetIO": "10KB / 10KB",
                "BlockIO": "0B / 0B",
                "PIDs": "4"
            }
        ]"#;

        let stats = parse_docker_stats_json(sample);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].id, "c100");
        assert_eq!(stats[0].name, "app");
        assert_eq!(stats[0].cpu_perc, "2.5%");
    }

    #[test]
    fn test_classify_docker_error() {
        // Daemon offline
        let offline_msg =
            "failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine";
        let classified = classify_docker_error(offline_msg);
        assert!(classified.contains("Docker daemon is not reachable"));

        let sock_offline = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?";
        let classified2 = classify_docker_error(sock_offline);
        assert!(classified2.contains("Docker daemon is not reachable"));

        // Docker missing
        let missing_cmd = "docker: command not found";
        let classified3 = classify_docker_error(missing_cmd);
        assert!(classified3.contains("Docker is not installed or not available"));
    }

    #[tokio::test]
    async fn test_docker_compose_up_guard_validations() {
        // Path traversal to forbidden system target
        let res_traversal = docker_compose_up(Some("/etc/shadow"), None).await;
        assert!(res_traversal.is_err());
        assert!(res_traversal.unwrap_err().contains("Security Violation"));

        // Invalid extension
        let res_invalid_ext = docker_compose_up(Some("docker-compose.sh"), None).await;
        assert!(res_invalid_ext.is_err());
        assert!(res_invalid_ext.unwrap_err().contains("expected a YAML"));

        // Invalid service name (injection attempt)
        let res_injection = docker_compose_up(None, Some("web; rm -rf /")).await;
        assert!(res_injection.is_err());
        assert!(
            res_injection
                .unwrap_err()
                .contains("Invalid characters in service name")
        );
    }

    #[tokio::test]
    async fn test_docker_restart_and_logs_injection_guard() {
        assert!(docker_restart("").await.is_err());
        assert!(docker_restart("container; reboot").await.is_err());
        assert!(docker_restart("`whoami`").await.is_err());

        assert!(docker_logs("", None).await.is_err());
        assert!(docker_logs("container && ls", None).await.is_err());
    }

    #[test]
    fn test_docker_logs_smart_compression() {
        let raw_logs = "2026-10-14 00:00:00 [info] server listening on port 8080\n\
                        2026-10-14 00:00:01 [info] health check ping\n\
                        2026-10-14 00:00:01 [info] health check ping\n\
                        2026-10-14 00:00:01 [info] health check ping\n\
                        2026-10-14 00:00:02 [error] database timeout connecting to postgres\n\
                        2026-10-14 00:00:03 [info] retry connecting\n";

        let compressed = compress_container_logs(raw_logs, "web_app");
        assert!(compressed.contains("Logs for container 'web_app'"));
        assert!(
            compressed.contains("[Repeated 3 times] 2026-10-14 00:00:01 [info] health check ping")
        );
        assert!(compressed.contains("[error] database timeout connecting to postgres"));
    }
}
