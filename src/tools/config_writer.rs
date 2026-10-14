//! Safe server configuration writer module with automatic backup,
//! syntax validation, and instant rollback on failure.

use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

/// Result summary of a configuration write operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConfigWriteResult {
    pub path: String,
    pub bytes_written: usize,
    pub backup_path: Option<String>,
    pub validation_output: Option<String>,
    pub status: String,
}

/// Safely writes a configuration file within allowed directories,
/// creating a timestamped backup, running validation, and rolling back if validation fails.
pub async fn write_server_config(
    path_str: &str,
    content: &str,
    validate_command: Option<&str>,
    allowed_dirs: &[PathBuf],
    security: &crate::config::SecurityConfig,
) -> Result<String, String> {
    let trimmed = path_str.trim();
    if trimmed.is_empty() {
        return Err("Configuration path cannot be empty".to_string());
    }

    let input_path = Path::new(trimmed);

    // 1. Lexical normalization & traversal check
    let normalized = crate::guard::fs_guard::normalize_path(input_path)
        .map_err(|e| format!("Invalid configuration path: {e}"))?;

    // 2. Validate against allowed configuration directories
    let is_allowed = allowed_dirs.iter().any(|allowed| {
        let norm_allowed =
            crate::guard::fs_guard::normalize_path(allowed).unwrap_or_else(|_| allowed.clone());
        normalized.starts_with(&norm_allowed)
    });

    if !is_allowed {
        return Err(format!(
            "Access to configuration path '{}' is denied: not within allowed directories {:?}",
            normalized.display(),
            allowed_dirs
        ));
    }

    // 3. Security Guard check (ensures not in critical auth/system blacklists)
    crate::guard::fs_guard::check_file_write_safety_with_config(&normalized, security)
        .map_err(|e| format!("Security Violation: {e}"))?;

    // Ensure parent directory exists
    if let Some(parent) = normalized.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            format!(
                "Failed to create configuration directory '{}': {e}",
                parent.display()
            )
        })?;
    }

    // 4 & 5. Atomic write with automatic backup and TOCTOU / symlink protection
    let write_res =
        crate::tools::file_ops::atomic_write_with_backup(&normalized, content.as_bytes(), true)
            .await?;

    let backup_path_opt = write_res.backup_path;
    if let Some(ref b) = backup_path_opt {
        info!(
            target = %normalized.display(),
            backup = %b.display(),
            "Configuration backup created successfully"
        );
    }

    // 6. Determine validation command
    let clean_str = normalized
        .to_string_lossy()
        .replace('\\', "/")
        .to_lowercase();
    let auto_cmd = if clean_str.starts_with("/etc/nginx") {
        Some("nginx -t")
    } else {
        None
    };

    let effective_validation = validate_command.or(auto_cmd);

    // 7. Execute validation command if specified
    if let Some(cmd_template) = effective_validation {
        let norm_display = normalized.to_string_lossy().replace('\\', "/");
        let cmd_to_run = cmd_template.replace("<path>", &norm_display);

        // Verify validation command is not malicious
        if let Err(violation) =
            crate::guard::check_command_safety_with_config(&cmd_to_run, security)
        {
            // Rollback on unsafe validation command
            rollback(&normalized, &backup_path_opt).await;
            return Err(format!(
                "Validation command rejected by security guard: {violation}. Successfully rolled back."
            ));
        }

        info!(command = %cmd_to_run, "Running configuration validation command");

        let validation_res =
            crate::executor::execute_command_with_smart_logs(&cmd_to_run, Duration::from_secs(15))
                .await;

        match validation_res {
            Ok(output) => {
                info!(target = %normalized.display(), "Configuration validation passed");
                let backup_str = backup_path_opt.map(|b| b.to_string_lossy().replace('\\', "/"));
                let result = ConfigWriteResult {
                    path: norm_display,
                    bytes_written: content.len(),
                    backup_path: backup_str,
                    validation_output: Some(output),
                    status: "success".to_string(),
                };
                serde_json::to_string_pretty(&result)
                    .map_err(|e| format!("Serialization error: {e}"))
            }
            Err(val_err) => {
                warn!(
                    target = %normalized.display(),
                    error = %val_err,
                    "Configuration validation failed, initiating rollback"
                );

                let rolled_back_msg = rollback(&normalized, &backup_path_opt).await;

                Err(format!(
                    "Configuration validation failed for '{}':\n{}\n\nRollback Status: {}",
                    normalized.display(),
                    val_err,
                    rolled_back_msg
                ))
            }
        }
    } else {
        let norm_display = normalized.to_string_lossy().replace('\\', "/");
        let backup_str = backup_path_opt.map(|b| b.to_string_lossy().replace('\\', "/"));
        let result = ConfigWriteResult {
            path: norm_display,
            bytes_written: content.len(),
            backup_path: backup_str,
            validation_output: None,
            status: "success".to_string(),
        };
        serde_json::to_string_pretty(&result).map_err(|e| format!("Serialization error: {e}"))
    }
}

/// Restores previous version from backup or removes newly created file on rollback.
async fn rollback(target: &Path, backup_path_opt: &Option<PathBuf>) -> String {
    if let Some(backup) = backup_path_opt {
        match tokio::fs::copy(backup, target).await {
            Ok(_) => format!(
                "Successfully restored original configuration from backup '{}'",
                backup.display()
            ),
            Err(e) => format!(
                "CRITICAL: Failed to restore backup '{}': {e}",
                backup.display()
            ),
        }
    } else {
        match tokio::fs::remove_file(target).await {
            Ok(_) => format!(
                "Successfully removed invalid new configuration file '{}'",
                target.display()
            ),
            Err(e) => format!(
                "Failed to remove invalid configuration file '{}': {e}",
                target.display()
            ),
        }
    }
}

// -----------------------------------------------------------------------------
// McpTool Implementation
// -----------------------------------------------------------------------------

use crate::mcp::protocol::CallToolResult;
use crate::tools::registry::{McpTool, ToolContext, ToolRegistry};
use async_trait::async_trait;

pub struct WriteServerConfigTool;

#[async_trait]
impl McpTool for WriteServerConfigTool {
    fn name(&self) -> &str {
        "write_server_config"
    }

    fn description(&self) -> &str {
        "Safely writes server configuration files (nginx, caddy, supervisor) with automatic timestamped backup, syntax validation, and instant rollback on failure."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the configuration file (must be inside allowed configuration directories)."
                },
                "content": {
                    "type": "string",
                    "description": "New configuration text content to write."
                },
                "validate_command": {
                    "type": "string",
                    "description": "Optional syntax validation command (e.g. 'nginx -t', 'caddy validate --config <path>'). Automatically defaults to 'nginx -t' for /etc/nginx/ files."
                }
            },
            "required": ["path", "content"]
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let path_arg = args.get("path").and_then(|p| p.as_str());
        let content_arg = args.get("content").and_then(|c| c.as_str());
        let validate_arg = args.get("validate_command").and_then(|v| v.as_str());

        match (path_arg, content_arg) {
            (Some(path), Some(content)) => {
                let allowed_dirs = &ctx.config.inspector.allowed_config_dirs;
                let security = &ctx.config.security;

                match write_server_config(path, content, validate_arg, allowed_dirs, security).await
                {
                    Ok(output) => Ok(CallToolResult::text(output)),
                    Err(e) => Ok(CallToolResult::error(e)),
                }
            }
            _ => Ok(CallToolResult::error(
                "Missing required parameters: 'path' (string) and 'content' (string)",
            )),
        }
    }
}

/// Registers the config writer tool into the given registry.
pub fn register_config_writer_tools(registry: &mut ToolRegistry) {
    registry.register_tool(WriteServerConfigTool);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_write_server_config_success_with_backup() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_test_cfg_writer_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let allowed_dirs = vec![temp_dir.clone()];
        let config_file = temp_dir.join("nginx.conf");
        let security = crate::config::SecurityConfig::default();

        // 1. Initial write
        tokio::fs::write(&config_file, "server { listen 80; }")
            .await
            .unwrap();

        // 2. Overwrite with valid config and validation command
        let res = write_server_config(
            config_file.to_str().unwrap(),
            "server { listen 8080; }",
            Some("echo syntax_ok"),
            &allowed_dirs,
            &security,
        )
        .await;

        assert!(res.is_ok());
        let res_json: ConfigWriteResult = serde_json::from_str(&res.unwrap()).unwrap();
        assert_eq!(res_json.status, "success");
        assert!(res_json.backup_path.is_some());

        // Verify current content was updated
        let current_content = tokio::fs::read_to_string(&config_file).await.unwrap();
        assert_eq!(current_content, "server { listen 8080; }");

        // Verify backup file preserved original content
        let backup_file = PathBuf::from(res_json.backup_path.unwrap());
        assert!(backup_file.exists());
        let backup_content = tokio::fs::read_to_string(&backup_file).await.unwrap();
        assert_eq!(backup_content, "server { listen 80; }");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_write_server_config_validation_failure_triggers_rollback() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_test_cfg_rollback_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let allowed_dirs = vec![temp_dir.clone()];
        let config_file = temp_dir.join("caddy.conf");
        let security = crate::config::SecurityConfig::default();

        // Initial valid content
        tokio::fs::write(&config_file, "original_working_content")
            .await
            .unwrap();

        // Attempt write with a validation command that simulates syntax error
        let fail_cmd = if cfg!(windows) {
            "cmd /C exit 1"
        } else {
            "sh -c 'exit 1'"
        };

        let res = write_server_config(
            config_file.to_str().unwrap(),
            "broken_new_content",
            Some(fail_cmd),
            &allowed_dirs,
            &security,
        )
        .await;

        assert!(res.is_err());
        let err_msg = res.unwrap_err();
        assert!(err_msg.contains("validation failed"));
        assert!(err_msg.contains("Successfully restored original configuration"));

        // Verify file was restored to original content
        let current_content = tokio::fs::read_to_string(&config_file).await.unwrap();
        assert_eq!(current_content, "original_working_content");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_write_server_config_denies_outside_allowed_dirs() {
        let allowed_dirs = vec![PathBuf::from("/etc/nginx")];
        let security = crate::config::SecurityConfig::default();

        let res = write_server_config(
            "/tmp/unallowed.conf",
            "test content",
            None,
            &allowed_dirs,
            &security,
        )
        .await;

        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .contains("denied: not within allowed directories")
        );
    }
}
