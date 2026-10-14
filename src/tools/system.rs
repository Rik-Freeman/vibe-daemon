//! System Inspector & Execution tools.
//! Implements `McpTool` for system status, safe configuration reading,
//! isolated command execution, port management, and service control.

use async_trait::async_trait;
use tracing::warn;

use crate::mcp::protocol::CallToolResult;
use crate::tools::registry::{McpTool, ToolContext, ToolRegistry};

// -----------------------------------------------------------------------------
// 1. GetSystemStatusTool
// -----------------------------------------------------------------------------

pub struct GetSystemStatusTool;

#[async_trait]
impl McpTool for GetSystemStatusTool {
    fn name(&self) -> &str {
        "get_system_status"
    }

    fn description(&self) -> &str {
        "Returns a comprehensive overview of the host system state, including memory usage, uptime, service statuses, and active listening ports."
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
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let status =
            crate::inspector::collect_system_status_with_config(&ctx.config.inspector).await;
        match serde_json::to_string_pretty(&status) {
            Ok(json_text) => Ok(CallToolResult::text(json_text)),
            Err(e) => Ok(CallToolResult::error(format!(
                "Failed to serialize system status: {e}"
            ))),
        }
    }
}

// -----------------------------------------------------------------------------
// 2. ReadServerConfigTool
// -----------------------------------------------------------------------------

pub struct ReadServerConfigTool;

#[async_trait]
impl McpTool for ReadServerConfigTool {
    fn name(&self) -> &str {
        "read_server_config"
    }

    fn description(&self) -> &str {
        "Safely reads a server configuration file (e.g. /etc/nginx/nginx.conf) with path traversal protection."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the configuration file to read (must be within allowed configuration directories)."
                }
            },
            "required": ["path"]
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let path_arg = args.get("path").and_then(|p| p.as_str());
        match path_arg {
            Some(path) => {
                let allowed_dirs = &ctx.config.inspector.allowed_config_dirs;
                match crate::inspector::safe_read_config_file(path, allowed_dirs).await {
                    Ok(content) => Ok(CallToolResult::text(content)),
                    Err(e) => Ok(CallToolResult::error(format!("{e}"))),
                }
            }
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'path' must be a string",
            )),
        }
    }
}

// -----------------------------------------------------------------------------
// 3. ExecuteSafeCommandTool
// -----------------------------------------------------------------------------

pub struct ExecuteSafeCommandTool;

#[async_trait]
impl McpTool for ExecuteSafeCommandTool {
    fn name(&self) -> &str {
        "execute_safe_command"
    }

    fn description(&self) -> &str {
        "Safely executes an allowed system command (e.g. cargo test, nginx -t, git status) with pattern guard filtering, port conflict arbitration, and a 30s timeout."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "System command string to execute."
                }
            },
            "required": ["command"]
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
                // 1. Check command safety via guard firewall with configured security rules
                if let Err(violation) =
                    crate::guard::check_command_safety_with_config(cmd, &ctx.config.security)
                {
                    warn!(command = %cmd, violation = %violation, "Command blocked by security guard");
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
                        warn!(command = %cmd, conflict = %conflict, "Command blocked due to port conflict");
                        Ok(CallToolResult::error(format!(
                            "Port Conflict Error: {}. Suggested alternative: port {}",
                            conflict.message, conflict.suggested_alternative_port
                        )))
                    } else {
                        // 3. Execute with bounded memory, concurrency, and configured limits
                        let limits = ctx.config.daemon.command_limits(None);
                        match crate::executor::execute_command_with_smart_logs_bounded(cmd, &limits)
                            .await
                        {
                            Ok(output) => Ok(CallToolResult::text(output)),
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

// -----------------------------------------------------------------------------
// 4. ManagePortTool
// -----------------------------------------------------------------------------

pub struct ManagePortTool;

#[async_trait]
impl McpTool for ManagePortTool {
    fn name(&self) -> &str {
        "manage_port"
    }

    fn description(&self) -> &str {
        "Safely manages firewall access rules (UFW/iptables) to open or close ports, strictly prohibiting closing critical ports such as SSH (port 22)."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["open", "close"],
                    "description": "Firewall action to perform: 'open' to allow traffic, or 'close' to deny traffic."
                },
                "port": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535,
                    "description": "Network port number (1-65535)."
                },
                "protocol": {
                    "type": "string",
                    "enum": ["tcp", "udp"],
                    "description": "Optional transport protocol ('tcp' or 'udp', defaults to 'tcp')."
                }
            },
            "required": ["action", "port"]
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let action_arg = args.get("action").and_then(|a| a.as_str());
        let port_arg = args.get("port").and_then(|p| p.as_u64()).map(|p| p as u16);
        let protocol_arg = args.get("protocol").and_then(|p| p.as_str());

        match (action_arg, port_arg) {
            (Some(action), Some(port)) => {
                match crate::guard::manage_firewall_port_with_config(
                    action,
                    port,
                    protocol_arg,
                    &ctx.config.security,
                )
                .await
                {
                    Ok(msg) => Ok(CallToolResult::text(msg)),
                    Err(violation) => {
                        warn!(action = %action, port = port, violation = %violation, "Port management blocked");
                        Ok(CallToolResult::error(format!(
                            "Security Violation: {violation}"
                        )))
                    }
                }
            }
            _ => Ok(CallToolResult::error(
                "Missing required parameters: 'action' (string) and 'port' (integer)",
            )),
        }
    }
}

// -----------------------------------------------------------------------------
// 5. ManageServiceTool
// -----------------------------------------------------------------------------

pub struct ManageServiceTool;

#[async_trait]
impl McpTool for ManageServiceTool {
    fn name(&self) -> &str {
        "manage_service"
    }

    fn description(&self) -> &str {
        "Safely manages system services (systemctl) such as nginx, with strict protection for critical daemons (vibe-daemon, sshd, network managers)."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "service_name": {
                    "type": "string",
                    "description": "Name of the system service (e.g. 'nginx')."
                },
                "action": {
                    "type": "string",
                    "enum": ["status", "restart", "reload"],
                    "description": "Action to perform on the service: 'status', 'restart', or 'reload'."
                }
            },
            "required": ["service_name", "action"]
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let service_arg = args.get("service_name").and_then(|s| s.as_str());
        let action_arg = args.get("action").and_then(|a| a.as_str());

        match (service_arg, action_arg) {
            (Some(service), Some(action)) => match crate::guard::manage_system_service_with_config(
                service,
                action,
                &ctx.config.security,
            )
            .await
            {
                Ok(msg) => Ok(CallToolResult::text(msg)),
                Err(violation) => {
                    warn!(service = %service, action = %action, violation = %violation, "Service management blocked");
                    Ok(CallToolResult::error(format!(
                        "Security Violation: {violation}"
                    )))
                }
            },
            _ => Ok(CallToolResult::error(
                "Missing required parameters: 'service_name' (string) and 'action' (string)",
            )),
        }
    }
}

/// Registers the 5 system inspector & management tools into the given registry.
pub fn register_system_tools(registry: &mut ToolRegistry) {
    registry.register_tool(GetSystemStatusTool);
    registry.register_tool(ReadServerConfigTool);
    registry.register_tool(ExecuteSafeCommandTool);
    registry.register_tool(ManagePortTool);
    registry.register_tool(ManageServiceTool);
}
