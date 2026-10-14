//! System inspection subsystem.
//! Collects host state information (listening ports, memory, uptime, services)
//! and provides secure configuration file reading with path traversal protection.

use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use tracing::{debug, warn};

// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------

/// Information about a listening network port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListeningPort {
    /// Protocol ("tcp", "udp", etc.)
    pub protocol: String,
    /// Local port number (e.g., 80, 443, 22)
    pub port: u16,
    /// Bound local address (e.g., "0.0.0.0", "127.0.0.1", "[::]")
    pub local_address: String,
    /// Associated process name (e.g., "nginx", "sshd") if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// Associated Process ID if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

/// Host memory usage metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
}

/// Status of a system daemon/service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceStatus {
    pub name: String,
    /// State string (e.g., "active", "inactive", "failed", "unknown")
    pub status: String,
}

/// Comprehensive overview of host system state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemStatus {
    pub hostname: String,
    pub uptime_seconds: u64,
    pub memory: MemoryInfo,
    pub services: Vec<ServiceStatus>,
    pub listening_ports: Vec<ListeningPort>,
}

/// Errors that can occur during safe configuration file inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    PathTraversal(String),
    AccessDenied(String),
    NotFound(String),
    PermissionDenied(String),
    FileTooLarge(String),
    Io(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathTraversal(msg) => write!(f, "Path traversal rejected: {msg}"),
            Self::AccessDenied(msg) => write!(f, "Access denied: {msg}"),
            Self::NotFound(msg) => write!(f, "File not found: {msg}"),
            Self::PermissionDenied(msg) => write!(f, "Permission denied: {msg}"),
            Self::FileTooLarge(msg) => write!(f, "File size limit exceeded: {msg}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

// -----------------------------------------------------------------------------
// Listening Ports Collection & Parsing
// -----------------------------------------------------------------------------

/// Parse `ss` command output (e.g. from `ss -tulpn` or `ss -tuln`).
pub fn parse_ss_output(output: &str) -> Vec<ListeningPort> {
    let mut ports = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Netid") || trimmed.starts_with("State") {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let protocol = parts[0].to_lowercase();
        if !protocol.starts_with("tcp") && !protocol.starts_with("udp") {
            continue;
        }

        // Find the column containing local address:port.
        // Usually column 4 (if State column exists: Netid, State, Recv-Q, Send-Q, Local Address:Port)
        // or column 3 (if State is omitted).
        let local_addr_col = parts.iter().skip(3).find(|col| col.contains(':'));
        let Some(local_addr_str) = local_addr_col else {
            continue;
        };

        let Some(colon_pos) = local_addr_str.rfind(':') else {
            continue;
        };

        let local_address = local_addr_str[..colon_pos].to_string();
        let port_str = &local_addr_str[colon_pos + 1..];

        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };

        // Extract process information if present (e.g., users:(("nginx",pid=1234,fd=6)))
        let mut process_name = None;
        let mut pid = None;

        if let Some(users_idx) = trimmed.find("users:((") {
            let user_part = &trimmed[users_idx..];
            // Process name is usually in quotes: ("nginx"
            if let Some(first_quote) = user_part.find('"')
                && let Some(second_quote) = user_part[first_quote + 1..].find('"')
            {
                let name = &user_part[first_quote + 1..first_quote + 1 + second_quote];
                process_name = Some(name.to_string());
            }
            // PID is formatted as pid=1234
            if let Some(pid_idx) = user_part.find("pid=") {
                let after_pid = &user_part[pid_idx + 4..];
                let digits: String = after_pid
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(p) = digits.parse::<u32>() {
                    pid = Some(p);
                }
            }
        }

        ports.push(ListeningPort {
            protocol,
            port,
            local_address,
            process_name,
            pid,
        });
    }

    ports
}

/// Collect listening ports on the host system.
/// Executes `ss -tulpn` or `ss -tuln`, or falls back gracefully if unavailable.
pub async fn collect_listening_ports() -> Vec<ListeningPort> {
    // Try running `ss -tulpn`
    let mut cmd1 = tokio::process::Command::new("ss");
    cmd1.args(["-tulpn"]);
    if let Some(stdout) = crate::executor::execute_quick_process(cmd1, 5).await {
        return parse_ss_output(&stdout);
    }

    debug!("ss -tulpn failed or not found, trying ss -tuln");

    // Fallback: try `ss -tuln`
    let mut cmd2 = tokio::process::Command::new("ss");
    cmd2.args(["-tuln"]);
    if let Some(stdout) = crate::executor::execute_quick_process(cmd2, 5).await {
        return parse_ss_output(&stdout);
    }

    warn!("System utility `ss` is unavailable on this host; returning empty listening ports list");
    Vec::new()
}

// -----------------------------------------------------------------------------
// Host Status, Memory & Uptime Collection
// -----------------------------------------------------------------------------

/// Parse Linux `/proc/meminfo` contents into `MemoryInfo`.
pub fn parse_proc_meminfo(content: &str) -> MemoryInfo {
    let mut total_kb = 0u64;
    let mut avail_kb = 0u64;
    let mut free_kb = 0u64;

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let Some(val_str) = parts.next() else {
            continue;
        };
        let Ok(val) = val_str.parse::<u64>() else {
            continue;
        };

        match key {
            "MemTotal:" => total_kb = val,
            "MemAvailable:" => avail_kb = val,
            "MemFree:" => free_kb = val,
            _ => {}
        }
    }

    let available = if avail_kb > 0 { avail_kb } else { free_kb };
    let total_bytes = total_kb * 1024;
    let available_bytes = available * 1024;
    let used_bytes = total_bytes.saturating_sub(available_bytes);

    MemoryInfo {
        total_bytes,
        available_bytes,
        used_bytes,
    }
}

/// Parse Linux `/proc/uptime` contents.
pub fn parse_proc_uptime(content: &str) -> u64 {
    content
        .split_whitespace()
        .next()
        .and_then(|val| val.parse::<f64>().ok())
        .map(|secs| secs as u64)
        .unwrap_or(0)
}

/// Collect memory information from `/proc/meminfo` or system defaults.
pub async fn collect_memory_info() -> MemoryInfo {
    if let Ok(content) = tokio::fs::read_to_string("/proc/meminfo").await {
        parse_proc_meminfo(&content)
    } else {
        debug!("/proc/meminfo unavailable");
        MemoryInfo::default()
    }
}

/// Collect uptime in seconds from `/proc/uptime` or system defaults.
pub async fn collect_uptime() -> u64 {
    if let Ok(content) = tokio::fs::read_to_string("/proc/uptime").await {
        parse_proc_uptime(&content)
    } else {
        0
    }
}

/// Check the status of a systemd daemon service using `systemctl is-active <service>`.
pub async fn check_service_status(service_name: &str) -> ServiceStatus {
    let mut cmd = tokio::process::Command::new("systemctl");
    cmd.args(["is-active", service_name]);
    let limits = crate::executor::CommandLimits {
        timeout: std::time::Duration::from_secs(5),
        max_stdout_bytes: 4096,
        max_stderr_bytes: 4096,
        termination_grace: std::time::Duration::from_millis(500),
    };
    let output = crate::executor::execute_process_bounded(cmd, &limits).await;

    let status = match output {
        Ok(out) => {
            let text = out.stdout_lossy().trim().to_string();
            if text.is_empty() {
                let err_text = out.stderr_lossy().trim().to_string();
                if err_text.is_empty() {
                    "inactive".to_string()
                } else {
                    err_text
                }
            } else {
                text
            }
        }
        Err(_) => "unknown".to_string(),
    };

    ServiceStatus {
        name: service_name.to_string(),
        status,
    }
}

/// Collect hostname from environment or `/etc/hostname`.
pub async fn collect_hostname() -> String {
    if let Ok(name) = std::env::var("HOSTNAME")
        && !name.trim().is_empty()
    {
        return name;
    }
    if let Ok(name) = std::env::var("COMPUTERNAME")
        && !name.trim().is_empty()
    {
        return name;
    }
    if let Ok(content) = tokio::fs::read_to_string("/etc/hostname").await {
        let name = content.trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }
    "localhost".to_string()
}

/// Collect an aggregated system status summary with dynamic inspector configuration.
pub async fn collect_system_status_with_config(
    config: &crate::config::InspectorConfig,
) -> SystemStatus {
    let hostname = collect_hostname().await;
    let uptime_seconds = collect_uptime().await;
    let memory = collect_memory_info().await;
    let listening_ports = collect_listening_ports().await;

    // Check key daemons dynamically from configuration
    let mut services = Vec::new();
    for svc in &config.key_services {
        services.push(check_service_status(svc).await);
    }

    SystemStatus {
        hostname,
        uptime_seconds,
        memory,
        services,
        listening_ports,
    }
}

/// Collect an aggregated system status summary using default inspector configuration.
pub async fn collect_system_status() -> SystemStatus {
    let default_config = crate::config::InspectorConfig::default();
    collect_system_status_with_config(&default_config).await
}

// -----------------------------------------------------------------------------
// Safe Configuration Reading (Path Traversal Protection)
// -----------------------------------------------------------------------------

/// Maximum allowed configuration file size (1 MB) to prevent OOM.
pub const MAX_CONFIG_FILE_SIZE_BYTES: u64 = 1024 * 1024;

/// Default allowed directories for configuration reading.
pub fn default_allowed_dirs() -> Vec<PathBuf> {
    let mut dirs = crate::config::default_allowed_config_dirs();

    if let Ok(extra) = std::env::var("VIBE_ALLOWED_CONFIG_DIRS") {
        for part in extra.split([';', ',']) {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                dirs.push(PathBuf::from(trimmed));
            }
        }
    }

    dirs
}

/// Lexically normalize a path to resolve `.` and `..` without requiring disk lookup.
pub fn normalize_path(path: &Path) -> Result<PathBuf, ConfigError> {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(p) => normalized.push(p.as_os_str()),
            Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR.to_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(ConfigError::PathTraversal(format!(
                        "Path '{}' attempts to traverse above root level",
                        path.display()
                    )));
                }
            }
            Component::Normal(c) => normalized.push(c),
        }
    }

    Ok(normalized)
}

/// Safely read a configuration file within the specified allowed directories.
/// Rejects path traversal attempts (`..`), symlink escapes, and paths outside allowed roots.
pub async fn safe_read_config_file(
    path_str: &str,
    allowed_dirs: &[PathBuf],
) -> Result<String, ConfigError> {
    let trimmed = path_str.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::NotFound("Path cannot be empty".to_string()));
    }

    let input_path = Path::new(trimmed);

    // 1. Lexical traversal check
    let normalized = normalize_path(input_path)?;

    // 2. Check if normalized path starts with any allowed directory
    let is_lexically_allowed = allowed_dirs.iter().any(|allowed| {
        let norm_allowed = normalize_path(allowed).unwrap_or_else(|_| allowed.clone());
        normalized.starts_with(&norm_allowed)
    });

    if !is_lexically_allowed {
        if input_path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(ConfigError::PathTraversal(format!(
                "path '{trimmed}' attempts to navigate outside allowed directories"
            )));
        }
        return Err(ConfigError::AccessDenied(format!(
            "Access to path '{trimmed}' is denied: not within allowed directories {allowed_dirs:?}"
        )));
    }

    // 3. Resolve canonical path on disk (protects against symlink directory escapes)
    let canonical_target = match tokio::fs::canonicalize(&normalized).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::NotFound(trimmed.to_string()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(ConfigError::PermissionDenied(trimmed.to_string()));
        }
        Err(e) => {
            return Err(ConfigError::Io(format!("I/O error resolving path: {e}")));
        }
    };

    // 4. Verify canonical path stays strictly inside allowed directories
    let is_canonically_allowed = allowed_dirs.iter().any(|allowed| {
        if let Ok(canon_allowed) = std::fs::canonicalize(allowed) {
            canonical_target.starts_with(&canon_allowed)
        } else {
            canonical_target.starts_with(allowed)
        }
    });

    if !is_canonically_allowed {
        return Err(ConfigError::PathTraversal(format!(
            "Symlink or path traversal escape detected for path '{trimmed}'"
        )));
    }

    // 5. Verify file metadata (size limit to prevent OOM)
    let metadata = match tokio::fs::metadata(&canonical_target).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::NotFound(trimmed.to_string()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(ConfigError::PermissionDenied(trimmed.to_string()));
        }
        Err(e) => return Err(ConfigError::Io(format!("Failed to read metadata: {e}"))),
    };

    if metadata.len() > MAX_CONFIG_FILE_SIZE_BYTES {
        return Err(ConfigError::FileTooLarge(format!(
            "File '{trimmed}' size ({} bytes) exceeds maximum limit of {} bytes (1 MB)",
            metadata.len(),
            MAX_CONFIG_FILE_SIZE_BYTES
        )));
    }

    // 6. Read file content safely
    match tokio::fs::read_to_string(&canonical_target).await {
        Ok(content) => Ok(content),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(
            ConfigError::PermissionDenied(format!("Permission denied reading {trimmed}")),
        ),
        Err(e) => Err(ConfigError::Io(format!("Failed to read file: {e}"))),
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss_output_complete() {
        let sample = r#"
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
tcp   LISTEN 0      128          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=1234,fd=6))
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=842,fd=3))
tcp   LISTEN 0      511        127.0.0.1:6379       0.0.0.0:*    users:(("redis-server",pid=910,fd=7))
udp   UNCONN 0      0            0.0.0.0:53         0.0.0.0:*    users:(("named",pid=450,fd=512))
tcp   LISTEN 0      128             [::]:443           [::]:*    users:(("nginx",pid=1234,fd=7))
"#;

        let ports = parse_ss_output(sample);
        assert_eq!(ports.len(), 5);

        assert_eq!(ports[0].protocol, "tcp");
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[0].local_address, "0.0.0.0");
        assert_eq!(ports[0].process_name.as_deref(), Some("nginx"));
        assert_eq!(ports[0].pid, Some(1234));

        assert_eq!(ports[1].port, 22);
        assert_eq!(ports[1].process_name.as_deref(), Some("sshd"));
        assert_eq!(ports[1].pid, Some(842));

        assert_eq!(ports[3].protocol, "udp");
        assert_eq!(ports[3].port, 53);
        assert_eq!(ports[3].process_name.as_deref(), Some("named"));

        assert_eq!(ports[4].port, 443);
        assert_eq!(ports[4].local_address, "[::]");
        assert_eq!(ports[4].process_name.as_deref(), Some("nginx"));
    }

    #[test]
    fn test_parse_proc_meminfo() {
        let sample = r#"
MemTotal:       16307380 kB
MemFree:         4120040 kB
MemAvailable:   11200420 kB
Buffers:          345120 kB
Cached:          6840212 kB
"#;
        let mem = parse_proc_meminfo(sample);
        assert_eq!(mem.total_bytes, 16307380 * 1024);
        assert_eq!(mem.available_bytes, 11200420 * 1024);
        assert_eq!(mem.used_bytes, (16307380 - 11200420) * 1024);
    }

    #[test]
    fn test_parse_proc_uptime() {
        let sample = "3600.45 14200.12\n";
        let uptime = parse_proc_uptime(sample);
        assert_eq!(uptime, 3600);
    }

    #[tokio::test]
    async fn test_safe_read_config_allowed_file() {
        let temp_dir = std::env::temp_dir().join(format!("vibe_test_{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let conf_file = temp_dir.join("test_nginx.conf");
        let content = "events {}\nhttp { server { listen 80; } }";
        tokio::fs::write(&conf_file, content).await.unwrap();

        let allowed_dirs = vec![temp_dir.clone()];
        let read_result = safe_read_config_file(conf_file.to_str().unwrap(), &allowed_dirs).await;

        assert!(read_result.is_ok());
        assert_eq!(read_result.unwrap(), content);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_safe_read_config_path_traversal_rejected() {
        let temp_dir = std::env::temp_dir().join(format!("vibe_test_trav_{}", std::process::id()));
        let sub_dir = temp_dir.join("sub");
        let _ = tokio::fs::create_dir_all(&sub_dir).await;

        let allowed_dirs = vec![sub_dir.clone()];
        let traversal_path = format!("{}/../../forbidden.conf", sub_dir.display());

        let result = safe_read_config_file(&traversal_path, &allowed_dirs).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::AccessDenied(_) | ConfigError::PathTraversal(_) => {}
            other => panic!("Expected path traversal or access denied error, got: {other:?}"),
        }

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_safe_read_config_file_not_found() {
        let temp_dir = std::env::temp_dir().join(format!("vibe_test_nf_{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let allowed_dirs = vec![temp_dir.clone()];
        let non_existent = temp_dir.join("missing.conf");

        let result = safe_read_config_file(non_existent.to_str().unwrap(), &allowed_dirs).await;
        assert!(matches!(result, Err(ConfigError::NotFound(_))));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_safe_read_config_file_too_large() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_test_toolarge_{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let large_file = temp_dir.join("large.conf");
        // Create file larger than 1MB (1MB + 1024 bytes)
        let data = vec![b'A'; (MAX_CONFIG_FILE_SIZE_BYTES + 1024) as usize];
        tokio::fs::write(&large_file, &data).await.unwrap();

        let allowed_dirs = vec![temp_dir.clone()];
        let result = safe_read_config_file(large_file.to_str().unwrap(), &allowed_dirs).await;
        assert!(matches!(result, Err(ConfigError::FileTooLarge(_))));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
