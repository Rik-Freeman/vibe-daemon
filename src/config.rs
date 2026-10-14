//! Configuration management for vibe-daemon.
//! Loads settings from TOML file with automatic fallback to safe defaults.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// Daemon Settings
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Logging verbosity level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Default command execution timeout in seconds.
    #[serde(default = "default_command_timeout_secs")]
    pub default_command_timeout_secs: u64,

    /// Maximum stdout bytes retained in memory before discarding excess stream bytes (default: 1 MB).
    #[serde(default = "default_max_stdout_bytes")]
    pub max_stdout_bytes: usize,

    /// Maximum stderr bytes retained in memory before discarding excess stream bytes (default: 1 MB).
    #[serde(default = "default_max_stderr_bytes")]
    pub max_stderr_bytes: usize,

    /// Grace period in milliseconds before forced process termination (default: 2000 ms).
    #[serde(default = "default_termination_grace_ms")]
    pub termination_grace_ms: u64,

    /// Optional path to structured JSONL audit log file (e.g. /var/log/vibe-daemon/audit.jsonl).
    #[serde(default)]
    pub audit_log_path: Option<PathBuf>,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_command_timeout_secs() -> u64 {
    30
}

pub fn default_max_stdout_bytes() -> usize {
    1_048_576
}

pub fn default_max_stderr_bytes() -> usize {
    1_048_576
}

pub fn default_termination_grace_ms() -> u64 {
    2000
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            default_command_timeout_secs: default_command_timeout_secs(),
            max_stdout_bytes: default_max_stdout_bytes(),
            max_stderr_bytes: default_max_stderr_bytes(),
            termination_grace_ms: default_termination_grace_ms(),
            audit_log_path: None,
        }
    }
}

impl DaemonConfig {
    /// Constructs a `CommandLimits` instance based on this configuration,
    /// optionally overriding the default timeout.
    pub fn command_limits(
        &self,
        override_timeout: Option<std::time::Duration>,
    ) -> crate::executor::CommandLimits {
        crate::executor::CommandLimits {
            timeout: override_timeout.unwrap_or_else(|| {
                std::time::Duration::from_secs(self.default_command_timeout_secs)
            }),
            max_stdout_bytes: self.max_stdout_bytes,
            max_stderr_bytes: self.max_stderr_bytes,
            termination_grace: std::time::Duration::from_millis(self.termination_grace_ms),
        }
    }
}

// -----------------------------------------------------------------------------
// Security Settings
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Ports that cannot be closed or blocked by AI commands (e.g. 22 for SSH).
    #[serde(default = "default_protected_ports")]
    pub protected_ports: Vec<u16>,

    /// Critical system daemons and services that cannot be stopped or disabled.
    #[serde(default = "default_protected_services")]
    pub protected_services: Vec<String>,

    /// Maximum total tool calls per minute allowed (default: 60). 0 disables global rate limiting.
    #[serde(default = "default_max_calls_per_minute")]
    pub max_calls_per_minute: u32,

    /// Optional per-tool limits per minute (e.g. execute_safe_command = 10).
    #[serde(default, alias = "tool_calls_per_minute")]
    pub tool_limits: HashMap<String, u32>,

    /// Optional list of paths protected from write operations.
    #[serde(default)]
    pub protected_write_paths: Vec<PathBuf>,

    /// Optional bearer auth token required for remote HTTP/SSE requests.
    /// If None or empty, authorization is not required.
    #[serde(default)]
    pub auth_token: Option<String>,
}

fn default_protected_ports() -> Vec<u16> {
    vec![22]
}

fn default_protected_services() -> Vec<String> {
    vec![
        "vibe-daemon".to_string(),
        "sshd".to_string(),
        "ssh".to_string(),
        "NetworkManager".to_string(),
        "systemd-networkd".to_string(),
        "networking".to_string(),
        "systemd-resolved".to_string(),
    ]
}

pub fn default_max_calls_per_minute() -> u32 {
    60
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            protected_ports: default_protected_ports(),
            protected_services: default_protected_services(),
            max_calls_per_minute: default_max_calls_per_minute(),
            tool_limits: HashMap::new(),
            protected_write_paths: Vec::new(),
            auth_token: None,
        }
    }
}

impl SecurityConfig {
    /// Validates whether a provided authorization header satisfies the configured bearer token requirement.
    /// Returns true if no token is configured, or if the header matches "Bearer <auth_token>".
    pub fn is_authorized(&self, auth_header: Option<&str>) -> bool {
        let Some(ref expected_token) = self.auth_token else {
            return true;
        };
        let trimmed_expected = expected_token.trim();
        if trimmed_expected.is_empty() {
            return true;
        }

        let Some(header) = auth_header else {
            return false;
        };

        let trimmed_header = header.trim();
        if let Some(token) = trimmed_header.strip_prefix("Bearer ") {
            token.trim() == trimmed_expected
        } else if let Some(token) = trimmed_header.strip_prefix("bearer ") {
            token.trim() == trimmed_expected
        } else {
            trimmed_header == trimmed_expected
        }
    }
}

// -----------------------------------------------------------------------------
// Inspector Settings
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InspectorConfig {
    /// Allowed base directories for safe configuration file reading.
    #[serde(default = "default_allowed_config_dirs")]
    pub allowed_config_dirs: Vec<PathBuf>,

    /// Key services inspected by default when querying system status.
    #[serde(default = "default_key_services")]
    pub key_services: Vec<String>,
}

pub fn default_key_services() -> Vec<String> {
    vec![
        "nginx".to_string(),
        "sshd".to_string(),
        "docker".to_string(),
        "postgresql".to_string(),
    ]
}

pub fn default_allowed_config_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/etc/nginx"),
        PathBuf::from("/etc/caddy"),
        PathBuf::from("/etc/supervisor"),
        PathBuf::from("/etc/haproxy"),
        PathBuf::from("/etc/letsencrypt"),
    ];

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

impl Default for InspectorConfig {
    fn default() -> Self {
        Self {
            allowed_config_dirs: default_allowed_config_dirs(),
            key_services: default_key_services(),
        }
    }
}

// -----------------------------------------------------------------------------
// Tasks Settings
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TasksConfig {
    /// Maximum concurrent active background tasks allowed (default: 8).
    #[serde(default = "default_max_active_tasks")]
    pub max_active_tasks: usize,

    /// Maximum total tasks retained in memory (active + history) (default: 100).
    #[serde(default = "default_max_retained_tasks")]
    pub max_retained_tasks: usize,

    /// Maximum output buffer size per task in bytes before truncation (default: 5 MB).
    #[serde(default = "default_output_limit_bytes")]
    pub output_limit_bytes: usize,

    /// Time-to-live in seconds for completed tasks before automatic cleanup (default: 3600 = 1 hour).
    #[serde(default = "default_completed_ttl_secs")]
    pub completed_ttl_secs: u64,

    /// Grace period in seconds for soft termination before SIGKILL (default: 3 seconds).
    #[serde(default = "default_termination_grace_secs")]
    pub termination_grace_secs: u64,
}

fn default_max_active_tasks() -> usize {
    8
}

fn default_max_retained_tasks() -> usize {
    100
}

fn default_output_limit_bytes() -> usize {
    5_242_880
}

fn default_completed_ttl_secs() -> u64 {
    3600
}

fn default_termination_grace_secs() -> u64 {
    3
}

impl Default for TasksConfig {
    fn default() -> Self {
        Self {
            max_active_tasks: default_max_active_tasks(),
            max_retained_tasks: default_max_retained_tasks(),
            output_limit_bytes: default_output_limit_bytes(),
            completed_ttl_secs: default_completed_ttl_secs(),
            termination_grace_secs: default_termination_grace_secs(),
        }
    }
}

// -----------------------------------------------------------------------------
// Audit Settings
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Optional path to structured JSONL audit log file.
    #[serde(default)]
    pub log_path: Option<PathBuf>,
}

/// Errors encountered during configuration loading, parsing, or validation.
#[derive(Debug)]
pub enum ConfigError {
    FileNotFound {
        path: PathBuf,
        source: std::io::Error,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::FileNotFound { path, source } => {
                write!(
                    f,
                    "Configuration file not found at '{}': {}",
                    path.display(),
                    source
                )
            }
            ConfigError::Io { path, source } => {
                write!(
                    f,
                    "Failed to read configuration file at '{}': {}",
                    path.display(),
                    source
                )
            }
            ConfigError::Parse { path, source } => {
                write!(
                    f,
                    "Invalid TOML syntax in configuration file '{}': {}",
                    path.display(),
                    source
                )
            }
            ConfigError::Validation(msg) => {
                write!(f, "Configuration validation error: {msg}")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::FileNotFound { source, .. } | ConfigError::Io { source, .. } => {
                Some(source)
            }
            ConfigError::Parse { source, .. } => Some(source.as_ref()),
            ConfigError::Validation(_) => None,
        }
    }
}

// -----------------------------------------------------------------------------
// Root Configuration
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub inspector: InspectorConfig,

    #[serde(default)]
    pub audit: AuditConfig,

    #[serde(default)]
    pub tasks: TasksConfig,
}

impl Config {
    /// Resolve configured audit log file path if set in either [audit] or [daemon] section.
    pub fn audit_log_path(&self) -> Option<&Path> {
        self.audit
            .log_path
            .as_deref()
            .or(self.daemon.audit_log_path.as_deref())
    }

    /// Load and validate configuration.
    ///
    /// - If `path` is None: returns default configuration with safe defaults.
    /// - If `path` is Some but the file does not exist: returns `Err(ConfigError::FileNotFound)` (fail-closed, no silent fallback).
    /// - If `path` is corrupted or fails TOML parsing: returns `Err(ConfigError::Parse)` (fail-closed).
    /// - If the configuration fails domain validation: returns `Err(ConfigError::Validation)` (fail-closed).
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let Some(path) = path else {
            let default_config = Self::default();
            default_config.validate()?;
            return Ok(default_config);
        };

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfigError::FileNotFound {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
            Err(err) => {
                return Err(ConfigError::Io {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        };

        let config: Config = toml::from_str(&content).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;

        config.validate()?;
        info!(path = %path.display(), "Successfully loaded and validated configuration");
        Ok(config)
    }

    /// Backwards-compatible loader that falls back to default on error.
    pub fn load_or_default(path: Option<&Path>) -> Self {
        Self::load(path).unwrap_or_else(|err| {
            warn!(error = %err, "Config load failed; falling back to default");
            Self::default()
        })
    }

    /// Validates all configuration constraints, bounds, and security invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // 1. Security protected ports
        if self.security.protected_ports.is_empty() {
            return Err(ConfigError::Validation(
                "security.protected_ports cannot be empty".to_string(),
            ));
        }
        let mut seen_ports = std::collections::HashSet::new();
        for &port in &self.security.protected_ports {
            if port == 0 {
                return Err(ConfigError::Validation(
                    "security.protected_ports contains invalid port 0".to_string(),
                ));
            }
            if !seen_ports.insert(port) {
                return Err(ConfigError::Validation(format!(
                    "Duplicate port {port} found in security.protected_ports"
                )));
            }
        }

        // 2. Security protected services
        if self.security.protected_services.is_empty() {
            return Err(ConfigError::Validation(
                "security.protected_services cannot be empty".to_string(),
            ));
        }
        let mut seen_services = std::collections::HashSet::new();
        for svc in &self.security.protected_services {
            let trimmed = svc.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::Validation(
                    "security.protected_services contains an empty service name".to_string(),
                ));
            }
            if !seen_services.insert(trimmed.to_lowercase()) {
                return Err(ConfigError::Validation(format!(
                    "Duplicate service '{trimmed}' found in security.protected_services"
                )));
            }
        }
        if self
            .security
            .auth_token
            .as_deref()
            .is_some_and(|token| token.trim().is_empty())
        {
            return Err(ConfigError::Validation(
                "security.auth_token cannot be empty when specified".to_string(),
            ));
        }

        // 3. Daemon bounds
        if self.daemon.default_command_timeout_secs == 0
            || self.daemon.default_command_timeout_secs > 3600
        {
            return Err(ConfigError::Validation(
                "daemon.default_command_timeout_secs must be between 1 and 3600 seconds"
                    .to_string(),
            ));
        }
        if self.daemon.max_stdout_bytes < 1024 || self.daemon.max_stdout_bytes > 104_857_600 {
            return Err(ConfigError::Validation(
                "daemon.max_stdout_bytes must be between 1024 (1 KB) and 104857600 (100 MB)"
                    .to_string(),
            ));
        }
        if self.daemon.max_stderr_bytes < 1024 || self.daemon.max_stderr_bytes > 104_857_600 {
            return Err(ConfigError::Validation(
                "daemon.max_stderr_bytes must be between 1024 (1 KB) and 104857600 (100 MB)"
                    .to_string(),
            ));
        }
        if self.daemon.termination_grace_ms < 100 || self.daemon.termination_grace_ms > 60_000 {
            return Err(ConfigError::Validation(
                "daemon.termination_grace_ms must be between 100 ms and 60000 ms".to_string(),
            ));
        }

        // 4. Inspector directories and key services
        if self.inspector.allowed_config_dirs.is_empty() {
            return Err(ConfigError::Validation(
                "inspector.allowed_config_dirs cannot be empty".to_string(),
            ));
        }
        for dir in &self.inspector.allowed_config_dirs {
            let dir_str = dir.to_string_lossy();
            if dir_str.contains("..") {
                return Err(ConfigError::Validation(format!(
                    "inspector.allowed_config_dirs path '{}' contains path traversal '..'",
                    dir.display()
                )));
            }
        }
        if self.inspector.key_services.is_empty() {
            return Err(ConfigError::Validation(
                "inspector.key_services cannot be empty".to_string(),
            ));
        }
        let mut seen_key_services = std::collections::HashSet::new();
        for svc in &self.inspector.key_services {
            let trimmed = svc.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::Validation(
                    "inspector.key_services contains an empty service name".to_string(),
                ));
            }
            if !seen_key_services.insert(trimmed.to_lowercase()) {
                return Err(ConfigError::Validation(format!(
                    "Duplicate service '{trimmed}' found in inspector.key_services"
                )));
            }
        }

        // 5. Protected write paths
        for path in &self.security.protected_write_paths {
            if path.to_string_lossy().contains("..") {
                return Err(ConfigError::Validation(format!(
                    "security.protected_write_paths '{}' contains path traversal '..'",
                    path.display()
                )));
            }
        }

        // 6. Tool limits
        for (tool, limit) in &self.security.tool_limits {
            if *limit > 100_000 {
                return Err(ConfigError::Validation(format!(
                    "security.tool_limits for '{tool}' exceeds maximum limit of 100000 calls/min"
                )));
            }
        }

        // 7. Background tasks bounds
        if self.tasks.max_active_tasks == 0 || self.tasks.max_active_tasks > 1000 {
            return Err(ConfigError::Validation(
                "tasks.max_active_tasks must be between 1 and 1000".to_string(),
            ));
        }
        if self.tasks.max_retained_tasks < self.tasks.max_active_tasks
            || self.tasks.max_retained_tasks > 100_000
        {
            return Err(ConfigError::Validation(
                "tasks.max_retained_tasks must be greater than or equal to max_active_tasks and <= 100000".to_string(),
            ));
        }
        if self.tasks.output_limit_bytes < 1024 || self.tasks.output_limit_bytes > 104_857_600 {
            return Err(ConfigError::Validation(
                "tasks.output_limit_bytes must be between 1024 (1 KB) and 104857600 (100 MB)"
                    .to_string(),
            ));
        }
        if self.tasks.completed_ttl_secs == 0 || self.tasks.completed_ttl_secs > 86400 * 365 {
            return Err(ConfigError::Validation(
                "tasks.completed_ttl_secs must be between 1 and 31536000 (1 year)".to_string(),
            ));
        }
        if self.tasks.termination_grace_secs == 0 || self.tasks.termination_grace_secs > 300 {
            return Err(ConfigError::Validation(
                "tasks.termination_grace_secs must be between 1 and 300 seconds".to_string(),
            ));
        }

        Ok(())
    }

    /// Load and parse configuration from a TOML string, validating it.
    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(content).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<string>"),
            source: Box::new(source),
        })?;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.daemon.log_level, "info");
        assert_eq!(config.daemon.default_command_timeout_secs, 30);
        assert_eq!(config.security.protected_ports, vec![22]);
        assert!(
            config
                .security
                .protected_services
                .contains(&"vibe-daemon".to_string())
        );
        assert!(
            config
                .security
                .protected_services
                .contains(&"sshd".to_string())
        );
        assert!(
            config
                .inspector
                .allowed_config_dirs
                .contains(&PathBuf::from("/etc/nginx"))
        );
        assert!(
            config
                .inspector
                .allowed_config_dirs
                .contains(&PathBuf::from("/etc/caddy"))
        );
        assert!(
            config
                .inspector
                .allowed_config_dirs
                .contains(&PathBuf::from("/etc/letsencrypt"))
        );
    }

    #[test]
    fn test_parse_empty_toml_returns_defaults() {
        let config: Config = toml::from_str("").expect("Empty TOML should parse");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn test_parse_partial_toml() {
        let toml_str = r#"
[daemon]
log_level = "debug"
default_command_timeout_secs = 60
"#;
        let config: Config = toml::from_str(toml_str).expect("Valid partial TOML");
        assert_eq!(config.daemon.log_level, "debug");
        assert_eq!(config.daemon.default_command_timeout_secs, 60);
        // Security and Inspector sections must retain defaults
        assert_eq!(config.security.protected_ports, vec![22]);
        assert!(
            config
                .inspector
                .allowed_config_dirs
                .contains(&PathBuf::from("/etc/nginx"))
        );
    }

    #[test]
    fn test_parse_custom_security_and_inspector() {
        let toml_str = r#"
[security]
protected_ports = [22, 3306, 5432]
protected_services = ["vibe-daemon", "sshd", "docker"]

[inspector]
allowed_config_dirs = ["/etc/nginx", "/var/www/config"]
"#;
        let config: Config = toml::from_str(toml_str).expect("Valid TOML");
        assert_eq!(config.security.protected_ports, vec![22, 3306, 5432]);
        assert_eq!(
            config.security.protected_services,
            vec!["vibe-daemon", "sshd", "docker"]
        );
        assert_eq!(
            config.inspector.allowed_config_dirs,
            vec![
                PathBuf::from("/etc/nginx"),
                PathBuf::from("/var/www/config")
            ]
        );
        assert_eq!(config.daemon.log_level, "info");
    }

    #[test]
    fn test_load_none_returns_default() {
        let config = Config::load(None).expect("Load with None should succeed with defaults");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn test_load_missing_file_returns_error() {
        let non_existent = Path::new("non_existent_config_file_xyz_123.toml");
        let result = Config::load(Some(non_existent));
        assert!(
            result.is_err(),
            "Loading a missing config file must return an error"
        );
        match result.unwrap_err() {
            ConfigError::FileNotFound { path, .. } => {
                assert_eq!(path, non_existent);
            }
            other => panic!("Expected FileNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn test_load_corrupted_toml_returns_error() {
        let temp_dir = std::env::temp_dir();
        let corrupt_path = temp_dir.join("vibe_corrupt_test.toml");
        std::fs::write(&corrupt_path, "invalid_toml = [unclosed").unwrap();

        let result = Config::load(Some(&corrupt_path));
        let _ = std::fs::remove_file(&corrupt_path);

        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Parse { path, .. } => {
                assert_eq!(path, corrupt_path);
            }
            other => panic!("Expected Parse error, got: {other:?}"),
        }
    }

    #[test]
    fn test_load_custom_key_services() {
        let toml_str = r#"
[inspector]
key_services = ["nginx", "caddy", "redis-server", "postgresql"]
"#;
        let config = Config::from_toml_str(toml_str).expect("Valid inspector config");
        assert_eq!(
            config.inspector.key_services,
            vec!["nginx", "caddy", "redis-server", "postgresql"]
        );
    }

    #[test]
    fn test_validate_port_zero_fails() {
        let toml_str = r#"
[security]
protected_ports = [0, 22]
"#;
        let result = Config::from_toml_str(toml_str);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Validation(msg) => assert!(msg.contains("invalid port 0")),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_duplicate_ports_fails() {
        let toml_str = r#"
[security]
protected_ports = [22, 80, 22]
"#;
        let result = Config::from_toml_str(toml_str);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Validation(msg) => assert!(msg.contains("Duplicate port 22")),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_empty_protected_ports_fails() {
        let toml_str = r#"
[security]
protected_ports = []
"#;
        let result = Config::from_toml_str(toml_str);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("protected_ports cannot be empty"))
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_invalid_timeout_fails() {
        let toml_str = r#"
[daemon]
default_command_timeout_secs = 0
"#;
        let result = Config::from_toml_str(toml_str);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Validation(msg) => assert!(msg.contains("default_command_timeout_secs")),
            other => panic!("Expected Validation error, got: {other:?}"),
        }

        let toml_too_large = r#"
[daemon]
default_command_timeout_secs = 5000
"#;
        let result2 = Config::from_toml_str(toml_too_large);
        assert!(result2.is_err());
    }

    #[test]
    fn test_validate_path_traversal_fails() {
        let toml_str = r#"
[inspector]
allowed_config_dirs = ["/etc/nginx/../root"]
"#;
        let result = Config::from_toml_str(toml_str);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Validation(msg) => assert!(msg.contains("path traversal '..'")),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_memory_limits_bounds_fails() {
        let toml_str = r#"
[daemon]
max_stdout_bytes = 100
"#;
        let result = Config::from_toml_str(toml_str);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Validation(msg) => assert!(msg.contains("max_stdout_bytes")),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_audit_config() {
        let toml_str = r#"
[audit]
log_path = "/var/log/vibe-daemon/audit.jsonl"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.audit_log_path(),
            Some(Path::new("/var/log/vibe-daemon/audit.jsonl"))
        );

        let toml_daemon_audit = r#"
[daemon]
audit_log_path = "/tmp/vibe_audit.jsonl"
"#;
        let config2: Config = toml::from_str(toml_daemon_audit).unwrap();
        assert_eq!(
            config2.audit_log_path(),
            Some(Path::new("/tmp/vibe_audit.jsonl"))
        );
    }

    #[test]
    fn test_parse_security_rate_limits() {
        let toml_str = r#"
[security]
max_calls_per_minute = 120

[security.tool_limits]
execute_safe_command = 15
get_system_status = 30
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.security.max_calls_per_minute, 120);
        assert_eq!(
            config.security.tool_limits.get("execute_safe_command"),
            Some(&15)
        );
        assert_eq!(
            config.security.tool_limits.get("get_system_status"),
            Some(&30)
        );
    }

    #[test]
    fn test_parse_daemon_bounded_limits() {
        let toml_str = r#"
[daemon]
default_command_timeout_secs = 45
max_stdout_bytes = 2097152
max_stderr_bytes = 524288
termination_grace_ms = 3500
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.daemon.default_command_timeout_secs, 45);
        assert_eq!(config.daemon.max_stdout_bytes, 2_097_152);
        assert_eq!(config.daemon.max_stderr_bytes, 524_288);
        assert_eq!(config.daemon.termination_grace_ms, 3500);

        let limits = config.daemon.command_limits(None);
        assert_eq!(limits.timeout, std::time::Duration::from_secs(45));
        assert_eq!(limits.max_stdout_bytes, 2_097_152);
        assert_eq!(limits.max_stderr_bytes, 524_288);
        assert_eq!(
            limits.termination_grace,
            std::time::Duration::from_millis(3500)
        );

        let override_limits = config
            .daemon
            .command_limits(Some(std::time::Duration::from_secs(10)));
        assert_eq!(override_limits.timeout, std::time::Duration::from_secs(10));
    }

    #[test]
    fn test_parse_tasks_config_and_validation() {
        let toml_str = r#"
[tasks]
max_active_tasks = 12
max_retained_tasks = 200
output_limit_bytes = 2097152
completed_ttl_secs = 7200
termination_grace_secs = 5
"#;
        let config = Config::from_toml_str(toml_str).unwrap();
        assert_eq!(config.tasks.max_active_tasks, 12);
        assert_eq!(config.tasks.max_retained_tasks, 200);
        assert_eq!(config.tasks.output_limit_bytes, 2_097_152);
        assert_eq!(config.tasks.completed_ttl_secs, 7200);
        assert_eq!(config.tasks.termination_grace_secs, 5);

        let invalid_active = r#"
[tasks]
max_active_tasks = 0
"#;
        assert!(Config::from_toml_str(invalid_active).is_err());

        let invalid_retained = r#"
[tasks]
max_active_tasks = 10
max_retained_tasks = 5
"#;
        assert!(Config::from_toml_str(invalid_retained).is_err());
    }

    #[test]
    fn test_unknown_fields_and_empty_auth_token_fail_closed() {
        assert!(Config::from_toml_str("[daemon]\nunknown_limit = 1").is_err());
        assert!(Config::from_toml_str("unknown_section = 1").is_err());
        assert!(Config::from_toml_str("[security]\nauth_token = '   '").is_err());
    }
}
