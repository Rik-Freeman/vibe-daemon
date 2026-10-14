pub mod protocol;

use crate::resources::ResourceError;
use protocol::{
    CallToolParams, CallToolResult, INVALID_PARAMS, INVALID_REQUEST, ImplementationInfo,
    InitializeResult, JsonRpcRequest, JsonRpcResponse, METHOD_NOT_FOUND, PARSE_ERROR,
    ServerCapabilities, ToolsCapability, ToolsListResult,
};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::{debug, error, info, warn};

pub const SERVER_NAME: &str = "vibe-daemon";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";

/// MCP Dispatcher handles incoming JSON-RPC requests and generates responses.
#[derive(Debug, Clone)]
pub struct McpDispatcher {
    pub config: std::sync::Arc<crate::config::Config>,
    pub audit_logger: std::sync::Arc<crate::audit::AuditLogger>,
    pub rate_limiter: std::sync::Arc<crate::rate_limiter::RateLimiter>,
    pub task_manager: std::sync::Arc<crate::tasks::TaskManager>,
    pub tool_registry: std::sync::Arc<crate::tools::ToolRegistry>,
    pub resource_registry: std::sync::Arc<crate::resources::ResourceRegistry>,
    pub subscription_manager: std::sync::Arc<crate::resources::SubscriptionManager>,
    pub event_bus: std::sync::Arc<crate::events::EventBus>,
    pub connected_client: std::sync::Arc<std::sync::RwLock<Option<String>>>,
}

impl Default for McpDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl McpDispatcher {
    pub fn new() -> Self {
        Self::with_config(crate::config::Config::default())
    }

    /// Construct a dispatcher with a given Config.
    pub fn with_config(config: crate::config::Config) -> Self {
        let audit_path = config.audit_log_path().map(|p| p.to_path_buf());
        let rate_limiter = crate::rate_limiter::RateLimiter::from_config(&config.security);
        let event_bus = std::sync::Arc::new(crate::events::EventBus::default());
        let mut task_manager = crate::tasks::TaskManager::with_config(config.tasks.clone());
        task_manager.set_event_bus(event_bus.clone());

        let cfg_arc = std::sync::Arc::new(config);
        let resource_registry =
            crate::resources::ResourceRegistry::default_registry(cfg_arc.clone());
        let subscription_manager = crate::resources::SubscriptionManager::new();
        Self {
            config: cfg_arc,
            audit_logger: std::sync::Arc::new(crate::audit::AuditLogger::new(audit_path)),
            rate_limiter: std::sync::Arc::new(rate_limiter),
            task_manager: std::sync::Arc::new(task_manager),
            tool_registry: std::sync::Arc::new(crate::tools::ToolRegistry::default_registry()),
            resource_registry: std::sync::Arc::new(resource_registry),
            subscription_manager: std::sync::Arc::new(subscription_manager),
            event_bus,
            connected_client: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Construct a dispatcher with a specific custom AuditLogger.
    pub fn with_audit_logger(mut self, logger: crate::audit::AuditLogger) -> Self {
        self.audit_logger = std::sync::Arc::new(logger);
        self
    }

    /// Construct a dispatcher with a specific custom RateLimiter.
    pub fn with_rate_limiter(mut self, rate_limiter: crate::rate_limiter::RateLimiter) -> Self {
        self.rate_limiter = std::sync::Arc::new(rate_limiter);
        self
    }

    /// Construct a dispatcher with a specific custom TaskManager.
    pub fn with_task_manager(mut self, task_manager: crate::tasks::TaskManager) -> Self {
        self.task_manager = std::sync::Arc::new(task_manager);
        self
    }

    /// Construct a dispatcher with a specific custom ToolRegistry.
    pub fn with_tool_registry(mut self, tool_registry: crate::tools::ToolRegistry) -> Self {
        self.tool_registry = std::sync::Arc::new(tool_registry);
        self
    }

    /// Construct a dispatcher with a specific custom ResourceRegistry.
    pub fn with_resource_registry(mut self, registry: crate::resources::ResourceRegistry) -> Self {
        self.resource_registry = std::sync::Arc::new(registry);
        self
    }

    /// Construct a dispatcher with a specific custom SubscriptionManager.
    pub fn with_subscription_manager(
        mut self,
        manager: crate::resources::SubscriptionManager,
    ) -> Self {
        self.subscription_manager = std::sync::Arc::new(manager);
        self
    }

    /// Construct a dispatcher with a specific custom EventBus.
    pub fn with_event_bus(mut self, event_bus: crate::events::EventBus) -> Self {
        self.event_bus = std::sync::Arc::new(event_bus);
        self
    }

    /// Trigger a server-initiated resource update notification on the event bus.
    pub async fn notify_resource_updated(&self, uri: &str) -> bool {
        self.event_bus
            .publish(crate::events::ServerEvent::ResourceUpdated {
                uri: uri.to_string(),
            })
            .await
    }

    /// Construct a dispatcher with specific allowed directories for configuration reading.
    pub fn with_allowed_dirs(dirs: Vec<PathBuf>) -> Self {
        let mut cfg = crate::config::Config::default();
        cfg.inspector.allowed_config_dirs = dirs;
        Self::with_config(cfg)
    }

    /// Process a single raw JSON-RPC text line asynchronously.
    /// Returns the JSON-RPC response string (if any).
    pub async fn handle_line(&self, line: &str) -> Option<String> {
        self.handle_line_with_session(line, None).await
    }

    /// Process a single raw JSON-RPC text line with session identification.
    pub async fn handle_line_with_session(
        &self,
        line: &str,
        session_id: Option<&str>,
    ) -> Option<String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(err) => {
                warn!(error = %err, raw_line = %trimmed, "Failed to parse JSON-RPC request");
                let error_resp =
                    JsonRpcResponse::error(None, PARSE_ERROR, format!("Parse error: {err}"));
                return serde_json::to_string(&error_resp).ok();
            }
        };

        if request.jsonrpc != "2.0" {
            warn!(version = %request.jsonrpc, "Invalid JSON-RPC protocol version");
            let error_resp = JsonRpcResponse::error(
                request.id,
                INVALID_REQUEST,
                "Invalid Request: jsonrpc must be '2.0'",
            );
            return serde_json::to_string(&error_resp).ok();
        }

        let response = self.handle_request_with_session(request, session_id).await;
        response.and_then(|resp| match serde_json::to_string(&resp) {
            Ok(serialized) => Some(serialized),
            Err(err) => {
                error!(error = %err, "Failed to serialize JSON-RPC response");
                None
            }
        })
    }

    /// Dispatch a parsed JSON-RPC request to the corresponding MCP method handler.
    pub async fn handle_request(&self, request: JsonRpcRequest) -> Option<JsonRpcResponse> {
        self.handle_request_with_session(request, None).await
    }

    /// Dispatch a parsed JSON-RPC request to the corresponding MCP method handler with session tracking.
    pub async fn handle_request_with_session(
        &self,
        request: JsonRpcRequest,
        session_id: Option<&str>,
    ) -> Option<JsonRpcResponse> {
        let method = request.method.as_str();
        debug!(method = %method, id = ?request.id, session = ?session_id, "Handling incoming MCP request");

        match method {
            "initialize" => Some(self.handle_initialize(request)),
            "notifications/initialized" | "initialized" => {
                self.handle_initialized_notification(request)
            }
            "tools/list" => Some(self.handle_tools_list(request)),
            "tools/call" => Some(self.handle_tools_call(request).await),
            "resources/list" => Some(self.handle_resources_list(request).await),
            "resources/read" => Some(self.handle_resources_read(request).await),
            "resources/subscribe" => {
                Some(self.handle_resources_subscribe(request, session_id).await)
            }
            "resources/unsubscribe" => {
                Some(self.handle_resources_unsubscribe(request, session_id).await)
            }
            "ping" => {
                // MCP specification ping handler
                request
                    .id
                    .map(|id| JsonRpcResponse::success(Some(id), serde_json::json!({})))
            }
            _ => {
                warn!(method = %method, "Unknown method requested");
                // If it's a request (has id), reply with METHOD_NOT_FOUND.
                // If it's a notification (no id), per JSON-RPC 2.0 no response is sent.
                request.id.map(|id| {
                    JsonRpcResponse::error(
                        Some(id),
                        METHOD_NOT_FOUND,
                        format!("Method '{method}' not found"),
                    )
                })
            }
        }
    }

    /// Handle the `initialize` method.
    fn handle_initialize(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        info!("Processing MCP initialize request");

        let protocol_version = if let Some(ref params) = request.params {
            if let Some(client_info) = params.get("clientInfo") {
                let name = client_info.get("name").and_then(|n| n.as_str());
                if let Some(n) = name
                    && let Ok(mut lock) = self.connected_client.write()
                {
                    *lock = Some(n.to_string());
                }
            }

            params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_PROTOCOL_VERSION)
                .to_string()
        } else {
            DEFAULT_PROTOCOL_VERSION.to_string()
        };

        let result = InitializeResult {
            protocol_version,
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                resources: Some(protocol::ResourcesCapability {
                    subscribe: Some(true),
                    list_changed: Some(false),
                }),
            },
            server_info: ImplementationInfo {
                name: SERVER_NAME.to_string(),
                version: SERVER_VERSION.to_string(),
            },
        };

        let result_value = match serde_json::to_value(result) {
            Ok(v) => v,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id,
                    protocol::INTERNAL_ERROR,
                    format!("Serialization error: {e}"),
                );
            }
        };

        JsonRpcResponse::success(request.id, result_value)
    }

    /// Handle the `notifications/initialized` notification / ack.
    fn handle_initialized_notification(&self, request: JsonRpcRequest) -> Option<JsonRpcResponse> {
        info!("Received initialization confirmation (ack)");
        // If caller sent an ID expecting a response/ack, return empty object; otherwise None (standard notification)
        request
            .id
            .map(|id| JsonRpcResponse::success(Some(id), serde_json::json!({})))
    }

    /// Handle the `tools/list` method. Returns registered inspection tools.
    fn handle_tools_list(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        debug!("Processing MCP tools/list request");

        let tools = self.tool_registry.list_tools();

        let result = ToolsListResult {
            tools,
            next_cursor: None,
        };

        let result_value = match serde_json::to_value(result) {
            Ok(v) => v,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id,
                    protocol::INTERNAL_ERROR,
                    format!("Serialization error: {e}"),
                );
            }
        };

        JsonRpcResponse::success(request.id, result_value)
    }

    /// Handle the `tools/call` method.
    async fn handle_tools_call(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        info!("Processing MCP tools/call request");

        let Some(params_value) = request.params else {
            return JsonRpcResponse::error(
                request.id,
                INVALID_PARAMS,
                "Missing params for tools/call",
            );
        };

        let call_params: CallToolParams = match serde_json::from_value(params_value) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id,
                    INVALID_PARAMS,
                    format!("Invalid params for tools/call: {e}"),
                );
            }
        };

        let tool_name = call_params.name.as_str();
        debug!(tool = %tool_name, "Executing tool call");

        let start_time = std::time::Instant::now();
        let tool_name_owned = call_params.name.clone();
        let arguments_owned = call_params
            .arguments
            .clone()
            .unwrap_or(serde_json::Value::Null);

        let tool_result = if let Err(rate_err) = self.rate_limiter.check_and_record(tool_name) {
            warn!(tool = %tool_name, error = %rate_err, "Tool call rejected due to rate limiting");
            CallToolResult::error(rate_err.to_string())
        } else if let Some(tool) = self.tool_registry.get(tool_name) {
            let client = self.connected_client.read().ok().and_then(|c| c.clone());
            let ctx = crate::tools::ToolContext::new(
                self.config.clone(),
                self.audit_logger.clone(),
                self.rate_limiter.clone(),
                self.task_manager.clone(),
                client,
            );
            match tool.execute(arguments_owned.clone(), &ctx).await {
                Ok(res) => res,
                Err(e) => CallToolResult::error(e),
            }
        } else {
            CallToolResult::error(format!("Unknown tool: '{tool_name}'"))
        };

        // Record structured audit trail entry
        let duration_ms = start_time.elapsed().as_millis() as u64;
        let (status, err_msg) = if tool_result.is_error.unwrap_or(false) {
            let msg = tool_result.content.first().map(|c| match c {
                protocol::ToolContent::Text { text } => text.clone(),
            });
            ("error", msg)
        } else {
            ("success", None)
        };
        let client = self.connected_client.read().ok().and_then(|c| c.clone());

        let mut audit_record = crate::audit::AuditRecord::new(
            tool_name_owned,
            arguments_owned,
            status,
            duration_ms,
            client,
        );
        if let Some(err) = err_msg {
            audit_record = audit_record.with_error(err);
        }
        self.audit_logger.log_async(audit_record);

        let result_value = match serde_json::to_value(tool_result) {
            Ok(v) => v,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id,
                    protocol::INTERNAL_ERROR,
                    format!("Serialization error: {e}"),
                );
            }
        };

        JsonRpcResponse::success(request.id, result_value)
    }

    /// Handle the `resources/list` method.
    async fn handle_resources_list(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        debug!("Processing MCP resources/list request");

        let cursor = request
            .params
            .as_ref()
            .and_then(|p| p.get("cursor"))
            .and_then(|c| c.as_str());

        match self.resource_registry.list(cursor).await {
            Ok(page) => match serde_json::to_value(page) {
                Ok(val) => JsonRpcResponse::success(request.id, val),
                Err(e) => JsonRpcResponse::error(
                    request.id,
                    protocol::INTERNAL_ERROR,
                    format!("Serialization error: {e}"),
                ),
            },
            Err(err) => {
                JsonRpcResponse::error(request.id, protocol::INTERNAL_ERROR, err.to_string())
            }
        }
    }

    /// Handle the `resources/read` method.
    async fn handle_resources_read(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        debug!("Processing MCP resources/read request");

        let uri_opt = request
            .params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|u| u.as_str());

        let uri = match uri_opt {
            Some(u) => u,
            None => {
                return JsonRpcResponse::error(
                    request.id,
                    INVALID_PARAMS,
                    "Missing required parameter: 'uri' must be a string",
                );
            }
        };

        match self.resource_registry.read(uri).await {
            Ok(content) => {
                let result = protocol::ResourcesReadResult {
                    contents: vec![content],
                };
                match serde_json::to_value(result) {
                    Ok(val) => JsonRpcResponse::success(request.id, val),
                    Err(e) => JsonRpcResponse::error(
                        request.id,
                        protocol::INTERNAL_ERROR,
                        format!("Serialization error: {e}"),
                    ),
                }
            }
            Err(ResourceError::NotFound(msg)) => {
                JsonRpcResponse::error(request.id, -32002, format!("Resource not found: {msg}"))
            }
            Err(ResourceError::AccessDenied(msg)) => {
                JsonRpcResponse::error(request.id, -32003, format!("Security Violation: {msg}"))
            }
            Err(ResourceError::LimitExceeded(msg)) => {
                JsonRpcResponse::error(request.id, -32004, format!("Limit exceeded: {msg}"))
            }
            Err(err) => {
                JsonRpcResponse::error(request.id, protocol::INTERNAL_ERROR, err.to_string())
            }
        }
    }

    /// Handle the `resources/subscribe` method.
    async fn handle_resources_subscribe(
        &self,
        request: JsonRpcRequest,
        session_id: Option<&str>,
    ) -> JsonRpcResponse {
        debug!("Processing MCP resources/subscribe request");

        let uri_opt = request
            .params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|u| u.as_str());

        let uri = match uri_opt {
            Some(u) => u,
            None => {
                return JsonRpcResponse::error(
                    request.id,
                    INVALID_PARAMS,
                    "Missing required parameter: 'uri' must be a string",
                );
            }
        };

        let sid = session_id.unwrap_or("default");
        match self.subscription_manager.subscribe(sid, uri).await {
            Ok(()) => JsonRpcResponse::success(request.id, serde_json::json!({})),
            Err(e) => JsonRpcResponse::error(request.id, INVALID_PARAMS, e),
        }
    }

    /// Handle the `resources/unsubscribe` method.
    async fn handle_resources_unsubscribe(
        &self,
        request: JsonRpcRequest,
        session_id: Option<&str>,
    ) -> JsonRpcResponse {
        debug!("Processing MCP resources/unsubscribe request");

        let uri_opt = request
            .params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|u| u.as_str());

        let uri = match uri_opt {
            Some(u) => u,
            None => {
                return JsonRpcResponse::error(
                    request.id,
                    INVALID_PARAMS,
                    "Missing required parameter: 'uri' must be a string",
                );
            }
        };

        let sid = session_id.unwrap_or("default");
        match self.subscription_manager.unsubscribe(sid, uri).await {
            Ok(_) => JsonRpcResponse::success(request.id, serde_json::json!({})),
            Err(e) => JsonRpcResponse::error(request.id, INVALID_PARAMS, e),
        }
    }

    /// Run the main event loop over an asynchronous reader and writer.
    /// Provides atomic, non-interleaved line serialization between request responses
    /// and server-initiated notifications.
    pub async fn run<R, W>(&self, reader: R, mut writer: W) -> anyhow::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut lines = BufReader::new(reader).lines();
        let mut event_rx = self.event_bus.subscribe();

        loop {
            tokio::select! {
                line_res = lines.next_line() => {
                    match line_res? {
                        Some(line) => {
                            if let Some(response_str) = self.handle_line_with_session(&line, Some("stdio")).await {
                                writer.write_all(response_str.as_bytes()).await?;
                                writer.write_all(b"\n").await?;
                                writer.flush().await?;
                            }
                        }
                        None => {
                            // Client disconnected (EOF)
                            break;
                        }
                    }
                }
                event_res = event_rx.recv() => {
                    if let Ok(event) = event_res {
                        let should_send = match &event {
                            crate::events::ServerEvent::ResourceUpdated { uri } => {
                                self.subscription_manager.is_subscribed("stdio", uri).await
                            }
                            _ => true,
                        };

                        if should_send {
                            let notif = event.to_jsonrpc_notification();
                            if let Ok(serialized) = serde_json::to_string(&notif) {
                                writer.write_all(serialized.as_bytes()).await?;
                                writer.write_all(b"\n").await?;
                                writer.flush().await?;
                            }
                        }
                    }
                }
            }
        }

        // Clean up any subscriptions for stdio session upon disconnect
        self.subscription_manager.cleanup_session("stdio").await;

        // Flush any remaining audit log records before exiting
        self.audit_logger.flush().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_initialize_handler() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["serverInfo"]["name"], "vibe-daemon");
        assert_eq!(resp["result"]["serverInfo"]["version"], "0.1.0");
        assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
        assert!(resp["result"]["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn test_initialized_notification_no_id() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        })
        .to_string();

        let response = dispatcher.handle_line(&raw).await;
        assert!(
            response.is_none(),
            "Notifications without ID must not return a response in JSON-RPC 2.0"
        );
    }

    #[tokio::test]
    async fn test_initialized_request_with_id() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "notifications/initialized",
            "params": {}
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected ack response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 99);
        assert_eq!(resp["result"], json!({}));
    }

    #[tokio::test]
    async fn test_tools_list_handler() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": "req-2",
            "method": "tools/list",
            "params": {}
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected tools/list response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], "req-2");

        let tools = resp["result"]["tools"]
            .as_array()
            .expect("tools must be an array");
        assert_eq!(tools.len(), 33);

        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"get_system_status"));
        assert!(names.contains(&"read_server_config"));
        assert!(names.contains(&"execute_safe_command"));
        assert!(names.contains(&"manage_port"));
        assert!(names.contains(&"manage_service"));
        assert!(names.contains(&"list_directory"));
        assert!(names.contains(&"read_file"));
        assert!(names.contains(&"write_file"));
        assert!(names.contains(&"search_files"));
        assert!(names.contains(&"tail_logs"));
        assert!(names.contains(&"write_server_config"));
        assert!(names.contains(&"get_disk_usage"));
        assert!(names.contains(&"get_cpu_info"));
        assert!(names.contains(&"get_top_processes"));
        assert!(names.contains(&"get_network_stats"));
        assert!(names.contains(&"tail_service_logs"));
        assert!(names.contains(&"start_background_task"));
        assert!(names.contains(&"check_task_status"));
        assert!(names.contains(&"get_task_output"));
        assert!(names.contains(&"cancel_task"));
        assert!(names.contains(&"docker_ps"));
        assert!(names.contains(&"docker_logs"));
        assert!(names.contains(&"docker_restart"));
        assert!(names.contains(&"docker_compose_up"));
        assert!(names.contains(&"docker_stats"));
        assert!(names.contains(&"nginx_test_config"));
        assert!(names.contains(&"nginx_reload"));
        assert!(names.contains(&"nginx_list_sites"));
        assert!(names.contains(&"nginx_enable_site"));
        assert!(names.contains(&"nginx_disable_site"));
        assert!(names.contains(&"ssl_check_expiry"));
        assert!(names.contains(&"ssl_list_certs"));
        assert!(names.contains(&"ssl_certbot_renew"));
    }

    #[tokio::test]
    async fn test_tools_call_background_tasks_lifecycle() {
        let dispatcher = McpDispatcher::new();

        // 1. Start background task
        let start_req = json!({
            "jsonrpc": "2.0",
            "id": "bg-1",
            "method": "tools/call",
            "params": {
                "name": "start_background_task",
                "arguments": {
                    "command": "echo mcp_bg_lifecycle_ok"
                }
            }
        })
        .to_string();

        let start_resp = dispatcher.handle_line(&start_req).await.unwrap();
        let start_val: serde_json::Value = serde_json::from_str(&start_resp).unwrap();
        assert_eq!(start_val["id"], "bg-1");
        assert!(
            start_val["result"]["isError"].is_null() || start_val["result"]["isError"] == false
        );
        let start_text = start_val["result"]["content"][0]["text"].as_str().unwrap();
        let start_json: serde_json::Value = serde_json::from_str(start_text).unwrap();
        let task_id = start_json["task_id"].as_str().unwrap();

        // 2. Poll check_task_status until completed
        let mut completed = false;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let status_req = json!({
                "jsonrpc": "2.0",
                "id": "bg-2",
                "method": "tools/call",
                "params": {
                    "name": "check_task_status",
                    "arguments": {
                        "task_id": task_id
                    }
                }
            })
            .to_string();
            let status_resp = dispatcher.handle_line(&status_req).await.unwrap();
            let status_val: serde_json::Value = serde_json::from_str(&status_resp).unwrap();
            let status_text = status_val["result"]["content"][0]["text"].as_str().unwrap();
            let report: serde_json::Value = serde_json::from_str(status_text).unwrap();
            if report["status"] == "Success" {
                assert_eq!(report["exit_code"], 0);
                completed = true;
                break;
            }
        }
        assert!(completed, "Background task should complete with Success");

        // 3. get_task_output
        let out_req = json!({
            "jsonrpc": "2.0",
            "id": "bg-3",
            "method": "tools/call",
            "params": {
                "name": "get_task_output",
                "arguments": {
                    "task_id": task_id,
                    "lines": 10
                }
            }
        })
        .to_string();
        let out_resp = dispatcher.handle_line(&out_req).await.unwrap();
        let out_val: serde_json::Value = serde_json::from_str(&out_resp).unwrap();
        let out_text = out_val["result"]["content"][0]["text"].as_str().unwrap();
        assert!(out_text.contains("mcp_bg_lifecycle_ok"));

        // 4. Test cancel_task with a long-running process
        let sleep_cmd = if cfg!(windows) {
            "powershell -Command \"Start-Sleep -Seconds 10\""
        } else {
            "sleep 10"
        };
        let start_sleep_req = json!({
            "jsonrpc": "2.0",
            "id": "bg-4",
            "method": "tools/call",
            "params": {
                "name": "start_background_task",
                "arguments": {
                    "command": sleep_cmd
                }
            }
        })
        .to_string();
        let sleep_resp = dispatcher.handle_line(&start_sleep_req).await.unwrap();
        let sleep_val: serde_json::Value = serde_json::from_str(&sleep_resp).unwrap();
        let sleep_text = sleep_val["result"]["content"][0]["text"].as_str().unwrap();
        let sleep_json: serde_json::Value = serde_json::from_str(sleep_text).unwrap();
        let sleep_task_id = sleep_json["task_id"].as_str().unwrap();

        let cancel_req = json!({
            "jsonrpc": "2.0",
            "id": "bg-5",
            "method": "tools/call",
            "params": {
                "name": "cancel_task",
                "arguments": {
                    "task_id": sleep_task_id
                }
            }
        })
        .to_string();
        let cancel_resp = dispatcher.handle_line(&cancel_req).await.unwrap();
        let cancel_val: serde_json::Value = serde_json::from_str(&cancel_resp).unwrap();
        let cancel_text = cancel_val["result"]["content"][0]["text"].as_str().unwrap();
        assert!(cancel_text.contains("successfully cancelled"));

        // 5. Test dangerous command blocked by Guard
        let dangerous_req = json!({
            "jsonrpc": "2.0",
            "id": "bg-6",
            "method": "tools/call",
            "params": {
                "name": "start_background_task",
                "arguments": {
                    "command": "rm -rf /"
                }
            }
        })
        .to_string();
        let dang_resp = dispatcher.handle_line(&dangerous_req).await.unwrap();
        let dang_val: serde_json::Value = serde_json::from_str(&dang_resp).unwrap();
        assert_eq!(dang_val["result"]["isError"], true);
        assert!(
            dang_val["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Security Violation")
        );
    }

    #[tokio::test]
    async fn test_tools_call_monitoring_tools() {
        let dispatcher = McpDispatcher::new();

        // 1. get_disk_usage
        let req_disk = json!({
            "jsonrpc": "2.0",
            "id": "mon-1",
            "method": "tools/call",
            "params": {
                "name": "get_disk_usage",
                "arguments": {}
            }
        })
        .to_string();
        let res_disk = dispatcher
            .handle_line(&req_disk)
            .await
            .expect("Disk response");
        let v_disk: serde_json::Value = serde_json::from_str(&res_disk).unwrap();
        assert_eq!(v_disk["id"], "mon-1");
        assert!(v_disk["result"]["isError"].is_null() || v_disk["result"]["isError"] == false);
        let disk_text = v_disk["result"]["content"][0]["text"].as_str().unwrap();
        let _: Vec<crate::tools::DiskUsage> = serde_json::from_str(disk_text).unwrap();

        // 2. get_cpu_info
        let req_cpu = json!({
            "jsonrpc": "2.0",
            "id": "mon-2",
            "method": "tools/call",
            "params": {
                "name": "get_cpu_info",
                "arguments": {}
            }
        })
        .to_string();
        let res_cpu = dispatcher
            .handle_line(&req_cpu)
            .await
            .expect("CPU response");
        let v_cpu: serde_json::Value = serde_json::from_str(&res_cpu).unwrap();
        assert_eq!(v_cpu["id"], "mon-2");
        assert!(v_cpu["result"]["isError"].is_null() || v_cpu["result"]["isError"] == false);
        let cpu_text = v_cpu["result"]["content"][0]["text"].as_str().unwrap();
        let _: crate::tools::CpuInfo = serde_json::from_str(cpu_text).unwrap();

        // 3. get_top_processes
        let req_procs = json!({
            "jsonrpc": "2.0",
            "id": "mon-3",
            "method": "tools/call",
            "params": {
                "name": "get_top_processes",
                "arguments": {
                    "limit": 5,
                    "sort_by": "cpu"
                }
            }
        })
        .to_string();
        let res_procs = dispatcher
            .handle_line(&req_procs)
            .await
            .expect("Processes response");
        let v_procs: serde_json::Value = serde_json::from_str(&res_procs).unwrap();
        assert_eq!(v_procs["id"], "mon-3");
        assert!(v_procs["result"]["isError"].is_null() || v_procs["result"]["isError"] == false);
        let procs_text = v_procs["result"]["content"][0]["text"].as_str().unwrap();
        let procs_list: Vec<crate::tools::ProcessInfo> = serde_json::from_str(procs_text).unwrap();
        assert!(procs_list.len() <= 5);

        // 4. get_network_stats
        let req_net = json!({
            "jsonrpc": "2.0",
            "id": "mon-4",
            "method": "tools/call",
            "params": {
                "name": "get_network_stats",
                "arguments": {}
            }
        })
        .to_string();
        let res_net = dispatcher
            .handle_line(&req_net)
            .await
            .expect("Network response");
        let v_net: serde_json::Value = serde_json::from_str(&res_net).unwrap();
        assert_eq!(v_net["id"], "mon-4");
        assert!(v_net["result"]["isError"].is_null() || v_net["result"]["isError"] == false);
        let net_text = v_net["result"]["content"][0]["text"].as_str().unwrap();
        let _: crate::tools::NetworkStats = serde_json::from_str(net_text).unwrap();

        // 5. tail_service_logs (safe)
        let req_logs = json!({
            "jsonrpc": "2.0",
            "id": "mon-5",
            "method": "tools/call",
            "params": {
                "name": "tail_service_logs",
                "arguments": {
                    "service_name": "nginx",
                    "lines": 20
                }
            }
        })
        .to_string();
        let res_logs = dispatcher
            .handle_line(&req_logs)
            .await
            .expect("Logs response");
        let v_logs: serde_json::Value = serde_json::from_str(&res_logs).unwrap();
        assert_eq!(v_logs["id"], "mon-5");
        assert!(v_logs["result"]["isError"].is_null() || v_logs["result"]["isError"] == false);

        // 6. tail_service_logs (blocked by guard)
        let req_blocked = json!({
            "jsonrpc": "2.0",
            "id": "mon-6",
            "method": "tools/call",
            "params": {
                "name": "tail_service_logs",
                "arguments": {
                    "service_name": "nginx; rm -rf /",
                    "lines": 10
                }
            }
        })
        .to_string();
        let res_blocked = dispatcher
            .handle_line(&req_blocked)
            .await
            .expect("Blocked response");
        let v_blocked: serde_json::Value = serde_json::from_str(&res_blocked).unwrap();
        assert_eq!(v_blocked["id"], "mon-6");
        assert_eq!(v_blocked["result"]["isError"], true);
        let blocked_text = v_blocked["result"]["content"][0]["text"].as_str().unwrap();
        assert!(blocked_text.contains("Security Violation"));
    }

    #[tokio::test]
    async fn test_tools_call_get_system_status() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "get_system_status",
                "arguments": {}
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected tools/call response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 10);
        assert!(resp["result"]["content"].is_array());

        let text_content = resp["result"]["content"][0]["text"].as_str().unwrap();
        let parsed_status: serde_json::Value = serde_json::from_str(text_content).unwrap();

        assert!(parsed_status.get("hostname").is_some());
        assert!(parsed_status.get("memory").is_some());
        assert!(parsed_status.get("services").is_some());
        assert!(parsed_status.get("listening_ports").is_some());
    }

    #[tokio::test]
    async fn test_tools_call_read_server_config_success() {
        let temp_dir = std::env::temp_dir().join(format!("vibe_mcp_test_{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let conf_file = temp_dir.join("nginx.conf");
        tokio::fs::write(&conf_file, "worker_processes auto;\n")
            .await
            .unwrap();

        let dispatcher = McpDispatcher::with_allowed_dirs(vec![temp_dir.clone()]);
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "read_server_config",
                "arguments": {
                    "path": conf_file.to_str().unwrap()
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected tools/call response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 11);
        assert_eq!(
            resp["result"]["content"][0]["text"].as_str().unwrap(),
            "worker_processes auto;\n"
        );
        assert!(resp["result"]["isError"].is_null() || resp["result"]["isError"] == false);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_tools_call_read_server_config_path_traversal() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_mcp_test_trav_{}", std::process::id()));
        let sub_dir = temp_dir.join("allowed_sub");
        let _ = tokio::fs::create_dir_all(&sub_dir).await;

        let dispatcher = McpDispatcher::with_allowed_dirs(vec![sub_dir.clone()]);
        let escape_path = format!("{}/../../secret.txt", sub_dir.display());

        let raw = json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "read_server_config",
                "arguments": {
                    "path": escape_path
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 12);
        assert_eq!(resp["result"]["isError"], true);

        let err_msg = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(err_msg.contains("Access denied") || err_msg.contains("Path traversal rejected"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_tools_call_unknown_tool() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "non_existent_tool",
                "arguments": {}
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["result"]["isError"], true);
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Unknown tool")
        );
    }

    #[tokio::test]
    async fn test_invalid_json() {
        let dispatcher = McpDispatcher::new();
        let response_str = dispatcher
            .handle_line("not-valid-json")
            .await
            .expect("Expected parse error");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["error"]["code"], PARSE_ERROR);
    }

    #[tokio::test]
    async fn test_method_not_found() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "non_existent_method"
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected error response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 5);
        assert_eq!(resp["error"]["code"], METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_dispatcher_async_stream() {
        let dispatcher = McpDispatcher::new();
        let input = format!(
            "{}\n{}\n",
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        );

        let reader = std::io::Cursor::new(input.into_bytes());
        let mut output = Vec::new();

        dispatcher.run(reader, &mut output).await.unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();

        assert_eq!(lines.len(), 2);
        let resp1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(resp1["id"], 1);
        assert_eq!(resp1["result"]["serverInfo"]["name"], "vibe-daemon");

        let resp2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(resp2["id"], 2);
        assert_eq!(resp2["result"]["tools"].as_array().unwrap().len(), 33);
    }

    #[tokio::test]
    async fn test_tools_call_execute_safe_command_blocks_dangerous() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {
                "name": "execute_safe_command",
                "arguments": {
                    "command": "rm -rf /"
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 14);
        assert_eq!(resp["result"]["isError"], true);
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Security Violation")
        );
    }

    #[tokio::test]
    async fn test_tools_call_execute_safe_command_success() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {
                "name": "execute_safe_command",
                "arguments": {
                    "command": "echo vibe_test_success"
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 15);
        assert!(resp["result"]["isError"].is_null() || resp["result"]["isError"] == false);
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("vibe_test_success")
        );
    }

    #[tokio::test]
    async fn test_tools_call_execute_safe_command_compresses_multiline_output() {
        let dispatcher = McpDispatcher::new();
        let cmd = if cfg!(windows) {
            "for /L %i in (1,1,25) do @echo line %i"
        } else {
            "seq 1 25"
        };

        let raw = json!({
            "jsonrpc": "2.0",
            "id": 16,
            "method": "tools/call",
            "params": {
                "name": "execute_safe_command",
                "arguments": {
                    "command": cmd
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 16);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("SUCCESS: Command completed in"));
        assert!(text.contains("[Output suppressed, no errors detected]"));
    }

    #[tokio::test]
    async fn test_tools_call_manage_port_blocks_port_22() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 17,
            "method": "tools/call",
            "params": {
                "name": "manage_port",
                "arguments": {
                    "action": "close",
                    "port": 22
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 17);
        assert_eq!(resp["result"]["isError"], true);
        let error_msg = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(error_msg.contains("Security Violation"));
        assert!(error_msg.contains("Closing critical SSH port (22) is strictly prohibited"));
    }

    #[tokio::test]
    async fn test_tools_call_manage_port_allows_open() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 18,
            "method": "tools/call",
            "params": {
                "name": "manage_port",
                "arguments": {
                    "action": "open",
                    "port": 8080
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 18);
        assert!(resp["result"]["isError"].is_null() || resp["result"]["isError"] == false);
    }

    #[tokio::test]
    async fn test_tools_call_manage_service_blocks_vibe_daemon_restart() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 19,
            "method": "tools/call",
            "params": {
                "name": "manage_service",
                "arguments": {
                    "service_name": "vibe-daemon",
                    "action": "restart"
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 19);
        assert_eq!(resp["result"]["isError"], true);
        let error_msg = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(error_msg.contains("Security Violation"));
        assert!(error_msg.contains("vibe-daemon"));
    }

    #[tokio::test]
    async fn test_tools_call_manage_service_blocks_sshd_restart() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "manage_service",
                "arguments": {
                    "service_name": "sshd",
                    "action": "restart"
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 20);
        assert_eq!(resp["result"]["isError"], true);
        let error_msg = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(error_msg.contains("Security Violation"));
        assert!(error_msg.contains("sshd"));
    }

    #[tokio::test]
    async fn test_tools_call_manage_service_allows_status() {
        let dispatcher = McpDispatcher::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "manage_service",
                "arguments": {
                    "service_name": "nginx",
                    "action": "status"
                }
            }
        })
        .to_string();

        let response_str = dispatcher
            .handle_line(&raw)
            .await
            .expect("Expected response");
        let resp: serde_json::Value = serde_json::from_str(&response_str).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 21);
        assert!(resp["result"]["isError"].is_null() || resp["result"]["isError"] == false);
    }

    #[tokio::test]
    async fn test_tools_call_rate_limit_exceeded_returns_mcp_error() {
        let limiter = crate::rate_limiter::RateLimiter::new(2, std::collections::HashMap::new());
        let dispatcher = McpDispatcher::new().with_rate_limiter(limiter);

        let make_req = |id: u64| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": "get_system_status",
                    "arguments": {}
                }
            })
            .to_string()
        };

        // First 2 calls succeed
        let r1 = dispatcher.handle_line(&make_req(1)).await.unwrap();
        let resp1: serde_json::Value = serde_json::from_str(&r1).unwrap();
        assert!(resp1["result"]["isError"].is_null());

        let r2 = dispatcher.handle_line(&make_req(2)).await.unwrap();
        let resp2: serde_json::Value = serde_json::from_str(&r2).unwrap();
        assert!(resp2["result"]["isError"].is_null());

        // 3rd call exceeds rate limit
        let r3 = dispatcher.handle_line(&make_req(3)).await.unwrap();
        let resp3: serde_json::Value = serde_json::from_str(&r3).unwrap();
        assert_eq!(resp3["jsonrpc"], "2.0");
        assert_eq!(resp3["id"], 3);
        assert_eq!(resp3["result"]["isError"], true);

        let error_text = resp3["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            error_text,
            "Rate limit exceeded: too many tool calls. Please wait a moment before retrying."
        );
    }

    #[tokio::test]
    async fn test_tools_call_tool_specific_rate_limit() {
        let mut tool_limits = std::collections::HashMap::new();
        tool_limits.insert("execute_safe_command".to_string(), 1);

        let limiter = crate::rate_limiter::RateLimiter::new(10, tool_limits);
        let dispatcher = McpDispatcher::new().with_rate_limiter(limiter);

        let cmd_req = |id: u64| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": "execute_safe_command",
                    "arguments": {
                        "command": "echo hello"
                    }
                }
            })
            .to_string()
        };

        // Call 1 for execute_safe_command succeeds
        let r1 = dispatcher.handle_line(&cmd_req(1)).await.unwrap();
        let resp1: serde_json::Value = serde_json::from_str(&r1).unwrap();
        assert!(resp1["result"]["isError"].is_null());

        // Call 2 for execute_safe_command exceeds tool limit
        let r2 = dispatcher.handle_line(&cmd_req(2)).await.unwrap();
        let resp2: serde_json::Value = serde_json::from_str(&r2).unwrap();
        assert_eq!(resp2["result"]["isError"], true);
        let err2 = resp2["result"]["content"][0]["text"].as_str().unwrap();
        assert!(err2.contains("Rate limit exceeded"));
        assert!(err2.contains("execute_safe_command"));

        // Other tools still succeed because global limit (10) is not reached
        let status_req = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_system_status",
                "arguments": {}
            }
        })
        .to_string();

        let r3 = dispatcher.handle_line(&status_req).await.unwrap();
        let resp3: serde_json::Value = serde_json::from_str(&r3).unwrap();
        assert!(resp3["result"]["isError"].is_null());
    }

    #[tokio::test]
    async fn test_tools_call_file_ops_lifecycle() {
        let dispatcher = McpDispatcher::new();
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_mcp_fileops_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let file_path = temp_dir.join("notes.txt");
        let path_str = file_path.to_string_lossy().replace('\\', "/");
        let dir_str = temp_dir.to_string_lossy().replace('\\', "/");

        // 1. write_file
        let write_req = json!({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {
                    "path": path_str,
                    "content": "line one\nline two\nline three"
                }
            }
        })
        .to_string();

        let w_resp = dispatcher.handle_line(&write_req).await.unwrap();
        let w_val: serde_json::Value = serde_json::from_str(&w_resp).unwrap();
        assert!(w_val["result"]["isError"].is_null());
        assert!(
            w_val["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Successfully wrote")
        );

        // 2. read_file
        let read_req = json!({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {
                    "path": path_str
                }
            }
        })
        .to_string();

        let r_resp = dispatcher.handle_line(&read_req).await.unwrap();
        let r_val: serde_json::Value = serde_json::from_str(&r_resp).unwrap();
        assert!(r_val["result"]["isError"].is_null());
        assert_eq!(
            r_val["result"]["content"][0]["text"].as_str().unwrap(),
            "line one\nline two\nline three"
        );

        // 3. list_directory
        let list_req = json!({
            "jsonrpc": "2.0",
            "id": 103,
            "method": "tools/call",
            "params": {
                "name": "list_directory",
                "arguments": {
                    "path": dir_str
                }
            }
        })
        .to_string();

        let l_resp = dispatcher.handle_line(&list_req).await.unwrap();
        let l_val: serde_json::Value = serde_json::from_str(&l_resp).unwrap();
        assert!(l_val["result"]["isError"].is_null());
        let l_text = l_val["result"]["content"][0]["text"].as_str().unwrap();
        assert!(l_text.contains("notes.txt"));

        // 4. search_files
        let search_req = json!({
            "jsonrpc": "2.0",
            "id": 104,
            "method": "tools/call",
            "params": {
                "name": "search_files",
                "arguments": {
                    "path": dir_str,
                    "pattern": "line two"
                }
            }
        })
        .to_string();

        let s_resp = dispatcher.handle_line(&search_req).await.unwrap();
        let s_val: serde_json::Value = serde_json::from_str(&s_resp).unwrap();
        assert!(s_val["result"]["isError"].is_null());
        let s_text = s_val["result"]["content"][0]["text"].as_str().unwrap();
        assert!(s_text.contains("line two"));

        // 5. tail_logs
        let tail_req = json!({
            "jsonrpc": "2.0",
            "id": 105,
            "method": "tools/call",
            "params": {
                "name": "tail_logs",
                "arguments": {
                    "path": path_str,
                    "lines": 2
                }
            }
        })
        .to_string();

        let t_resp = dispatcher.handle_line(&tail_req).await.unwrap();
        let t_val: serde_json::Value = serde_json::from_str(&t_resp).unwrap();
        assert!(t_val["result"]["isError"].is_null());
        let t_text = t_val["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(t_text, "line two\nline three");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_tools_call_write_file_blocks_protected_system_file() {
        let dispatcher = McpDispatcher::new();

        let write_req = json!({
            "jsonrpc": "2.0",
            "id": 106,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {
                    "path": "/etc/shadow",
                    "content": "root:evil_hash:0:0:..."
                }
            }
        })
        .to_string();

        let resp_str = dispatcher.handle_line(&write_req).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let err_text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(err_text.contains("Security Violation"));
        assert!(err_text.contains("forbidden"));
    }

    #[tokio::test]
    async fn test_tools_call_read_file_blocks_protected_system_file() {
        let dispatcher = McpDispatcher::new();

        let read_req = json!({
            "jsonrpc": "2.0",
            "id": 107,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {
                    "path": "/etc/shadow"
                }
            }
        })
        .to_string();

        let resp_str = dispatcher.handle_line(&read_req).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let err_text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(err_text.contains("Security Violation"));
    }

    #[tokio::test]
    async fn test_tools_call_write_server_config_success_and_backup() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_mcp_cfg_write_{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let conf_file = temp_dir.join("nginx.conf");
        tokio::fs::write(&conf_file, "events {}\n").await.unwrap();

        let dispatcher = McpDispatcher::with_allowed_dirs(vec![temp_dir.clone()]);
        let write_req = json!({
            "jsonrpc": "2.0",
            "id": 108,
            "method": "tools/call",
            "params": {
                "name": "write_server_config",
                "arguments": {
                    "path": conf_file.to_str().unwrap(),
                    "content": "events { worker_connections 1024; }\n",
                    "validate_command": "echo config_syntax_valid"
                }
            }
        })
        .to_string();

        let resp_str = dispatcher.handle_line(&write_req).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
        assert!(resp["result"]["isError"].is_null() || resp["result"]["isError"] == false);

        let content_str = resp["result"]["content"][0]["text"].as_str().unwrap();
        let parsed_res: serde_json::Value = serde_json::from_str(content_str).unwrap();
        assert_eq!(parsed_res["status"], "success");
        assert!(parsed_res["backup_path"].is_string());

        // Verify content updated
        let updated = tokio::fs::read_to_string(&conf_file).await.unwrap();
        assert_eq!(updated, "events { worker_connections 1024; }\n");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_tools_call_write_server_config_validation_failure_rollback() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_mcp_cfg_rollback_{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let conf_file = temp_dir.join("caddy.conf");
        tokio::fs::write(&conf_file, "localhost:8080\n")
            .await
            .unwrap();

        let fail_cmd = if cfg!(windows) {
            "cmd /C exit 1"
        } else {
            "sh -c 'exit 1'"
        };

        let dispatcher = McpDispatcher::with_allowed_dirs(vec![temp_dir.clone()]);
        let write_req = json!({
            "jsonrpc": "2.0",
            "id": 109,
            "method": "tools/call",
            "params": {
                "name": "write_server_config",
                "arguments": {
                    "path": conf_file.to_str().unwrap(),
                    "content": "broken syntax error",
                    "validate_command": fail_cmd
                }
            }
        })
        .to_string();

        let resp_str = dispatcher.handle_line(&write_req).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
        assert_eq!(resp["result"]["isError"], true);

        let err_text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(err_text.contains("validation failed"));
        assert!(err_text.contains("Successfully restored original configuration"));

        // Verify content remained unchanged
        let restored = tokio::fs::read_to_string(&conf_file).await.unwrap();
        assert_eq!(restored, "localhost:8080\n");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_tools_call_write_server_config_denies_outside_allowed_dirs() {
        let dispatcher =
            McpDispatcher::with_allowed_dirs(vec![std::path::PathBuf::from("/etc/nginx")]);
        let write_req = json!({
            "jsonrpc": "2.0",
            "id": 110,
            "method": "tools/call",
            "params": {
                "name": "write_server_config",
                "arguments": {
                    "path": "/var/log/forbidden.conf",
                    "content": "some text"
                }
            }
        })
        .to_string();

        let resp_str = dispatcher.handle_line(&write_req).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let err_text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(err_text.contains("denied: not within allowed directories"));
    }

    #[tokio::test]
    async fn test_tools_call_docker_manager() {
        let dispatcher = McpDispatcher::new();

        // 1. docker_ps call
        let ps_req = json!({
            "jsonrpc": "2.0",
            "id": 201,
            "method": "tools/call",
            "params": {
                "name": "docker_ps",
                "arguments": {
                    "all": true
                }
            }
        })
        .to_string();

        let ps_resp_str = dispatcher.handle_line(&ps_req).await.unwrap();
        let ps_resp: serde_json::Value = serde_json::from_str(&ps_resp_str).unwrap();
        assert_eq!(ps_resp["id"], 201);
        let ps_content = ps_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!ps_content.is_empty());

        // 2. docker_logs guard injection protection
        let logs_inj_req = json!({
            "jsonrpc": "2.0",
            "id": 202,
            "method": "tools/call",
            "params": {
                "name": "docker_logs",
                "arguments": {
                    "container_name_or_id": "web; cat /etc/shadow"
                }
            }
        })
        .to_string();

        let logs_resp_str = dispatcher.handle_line(&logs_inj_req).await.unwrap();
        let logs_resp: serde_json::Value = serde_json::from_str(&logs_resp_str).unwrap();
        assert_eq!(logs_resp["result"]["isError"], true);
        let logs_err = logs_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(logs_err.contains("Security Violation"));

        // 3. docker_restart guard injection protection
        let restart_inj_req = json!({
            "jsonrpc": "2.0",
            "id": 203,
            "method": "tools/call",
            "params": {
                "name": "docker_restart",
                "arguments": {
                    "container_name_or_id": "db && reboot"
                }
            }
        })
        .to_string();

        let restart_resp_str = dispatcher.handle_line(&restart_inj_req).await.unwrap();
        let restart_resp: serde_json::Value = serde_json::from_str(&restart_resp_str).unwrap();
        assert_eq!(restart_resp["result"]["isError"], true);
        let restart_err = restart_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(restart_err.contains("Security Violation"));

        // 4. docker_compose_up forbidden path
        let compose_req = json!({
            "jsonrpc": "2.0",
            "id": 204,
            "method": "tools/call",
            "params": {
                "name": "docker_compose_up",
                "arguments": {
                    "file_path": "/etc/shadow"
                }
            }
        })
        .to_string();

        let compose_resp_str = dispatcher.handle_line(&compose_req).await.unwrap();
        let compose_resp: serde_json::Value = serde_json::from_str(&compose_resp_str).unwrap();
        assert_eq!(compose_resp["result"]["isError"], true);
        let compose_err = compose_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(compose_err.contains("Security Violation"));

        // 5. docker_stats call
        let stats_req = json!({
            "jsonrpc": "2.0",
            "id": 205,
            "method": "tools/call",
            "params": {
                "name": "docker_stats",
                "arguments": {}
            }
        })
        .to_string();

        let stats_resp_str = dispatcher.handle_line(&stats_req).await.unwrap();
        let stats_resp: serde_json::Value = serde_json::from_str(&stats_resp_str).unwrap();
        assert_eq!(stats_resp["id"], 205);
        let stats_content = stats_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!stats_content.is_empty());
    }

    #[tokio::test]
    async fn test_tools_call_webserver_manager() {
        let dispatcher = McpDispatcher::new();

        // 1. nginx_test_config (default config)
        let test_cfg_req = json!({
            "jsonrpc": "2.0",
            "id": 301,
            "method": "tools/call",
            "params": {
                "name": "nginx_test_config",
                "arguments": {}
            }
        })
        .to_string();

        let test_resp_str = dispatcher.handle_line(&test_cfg_req).await.unwrap();
        let test_resp: serde_json::Value = serde_json::from_str(&test_resp_str).unwrap();
        assert_eq!(test_resp["id"], 301);
        let test_content = test_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!test_content.is_empty());

        // 2. nginx_test_config with forbidden file (/etc/shadow)
        let forbidden_req = json!({
            "jsonrpc": "2.0",
            "id": 302,
            "method": "tools/call",
            "params": {
                "name": "nginx_test_config",
                "arguments": {
                    "config_path": "/etc/shadow"
                }
            }
        })
        .to_string();

        let forb_resp_str = dispatcher.handle_line(&forbidden_req).await.unwrap();
        let forb_resp: serde_json::Value = serde_json::from_str(&forb_resp_str).unwrap();
        assert_eq!(forb_resp["id"], 302);
        assert_eq!(forb_resp["result"]["isError"], true);
        let forb_err = forb_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(forb_err.contains("Security Violation"));

        // 3. nginx_test_config outside allowed directories
        let outside_req = json!({
            "jsonrpc": "2.0",
            "id": 303,
            "method": "tools/call",
            "params": {
                "name": "nginx_test_config",
                "arguments": {
                    "config_path": "/var/log/nginx/bad.conf"
                }
            }
        })
        .to_string();

        let out_resp_str = dispatcher.handle_line(&outside_req).await.unwrap();
        let out_resp: serde_json::Value = serde_json::from_str(&out_resp_str).unwrap();
        assert_eq!(out_resp["id"], 303);
        assert_eq!(out_resp["result"]["isError"], true);
        let out_err = out_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(out_err.contains("denied: not within allowed directories"));

        // 4. nginx_reload
        let reload_req = json!({
            "jsonrpc": "2.0",
            "id": 304,
            "method": "tools/call",
            "params": {
                "name": "nginx_reload",
                "arguments": {}
            }
        })
        .to_string();

        let reload_resp_str = dispatcher.handle_line(&reload_req).await.unwrap();
        let reload_resp: serde_json::Value = serde_json::from_str(&reload_resp_str).unwrap();
        assert_eq!(reload_resp["id"], 304);
        let reload_content = reload_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(!reload_content.is_empty());

        // 5. nginx_list_sites
        let list_req = json!({
            "jsonrpc": "2.0",
            "id": 305,
            "method": "tools/call",
            "params": {
                "name": "nginx_list_sites",
                "arguments": {}
            }
        })
        .to_string();

        let list_resp_str = dispatcher.handle_line(&list_req).await.unwrap();
        let list_resp: serde_json::Value = serde_json::from_str(&list_resp_str).unwrap();
        assert_eq!(list_resp["id"], 305);
        let list_content = list_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!list_content.is_empty());

        // 6. nginx_enable_site injection protection
        let enable_inj_req = json!({
            "jsonrpc": "2.0",
            "id": 306,
            "method": "tools/call",
            "params": {
                "name": "nginx_enable_site",
                "arguments": {
                    "site_name": "app; rm -rf /"
                }
            }
        })
        .to_string();

        let en_resp_str = dispatcher.handle_line(&enable_inj_req).await.unwrap();
        let en_resp: serde_json::Value = serde_json::from_str(&en_resp_str).unwrap();
        assert_eq!(en_resp["id"], 306);
        assert_eq!(en_resp["result"]["isError"], true);
        let en_err = en_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(en_err.contains("Invalid characters") || en_err.contains("strictly prohibited"));

        // 7. nginx_disable_site traversal protection
        let disable_inj_req = json!({
            "jsonrpc": "2.0",
            "id": 307,
            "method": "tools/call",
            "params": {
                "name": "nginx_disable_site",
                "arguments": {
                    "site_name": "../etc/shadow"
                }
            }
        })
        .to_string();

        let dis_resp_str = dispatcher.handle_line(&disable_inj_req).await.unwrap();
        let dis_resp: serde_json::Value = serde_json::from_str(&dis_resp_str).unwrap();
        assert_eq!(dis_resp["id"], 307);
        assert_eq!(dis_resp["result"]["isError"], true);
        let dis_err = dis_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(dis_err.contains("Path traversal") || dis_err.contains("strictly prohibited"));
    }

    #[tokio::test]
    async fn test_tools_call_ssl_manager() {
        let dispatcher = McpDispatcher::new();

        // 1. tools/call: ssl_check_expiry (scan directories)
        let expiry_req = json!({
            "jsonrpc": "2.0",
            "id": 401,
            "method": "tools/call",
            "params": {
                "name": "ssl_check_expiry",
                "arguments": {}
            }
        })
        .to_string();

        let expiry_resp_str = dispatcher.handle_line(&expiry_req).await.unwrap();
        let expiry_resp: serde_json::Value = serde_json::from_str(&expiry_resp_str).unwrap();
        assert_eq!(expiry_resp["id"], 401);
        assert!(
            expiry_resp["result"]["isError"].is_null() || expiry_resp["result"]["isError"] == false
        );
        let summary_text = expiry_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        let summary: crate::tools::SslExpirySummary = serde_json::from_str(summary_text).unwrap();
        assert_eq!(summary.total_certificates, summary.certificates.len());

        // 2. tools/call: ssl_list_certs
        let list_req = json!({
            "jsonrpc": "2.0",
            "id": 402,
            "method": "tools/call",
            "params": {
                "name": "ssl_list_certs",
                "arguments": {}
            }
        })
        .to_string();

        let list_resp_str = dispatcher.handle_line(&list_req).await.unwrap();
        let list_resp: serde_json::Value = serde_json::from_str(&list_resp_str).unwrap();
        assert_eq!(list_resp["id"], 402);
        assert!(
            list_resp["result"]["isError"].is_null() || list_resp["result"]["isError"] == false
        );
        let list_text = list_resp["result"]["content"][0]["text"].as_str().unwrap();
        let _: Vec<crate::tools::SslCertificateInfo> = serde_json::from_str(list_text).unwrap();

        // 3. tools/call: ssl_certbot_renew (dry_run: true)
        let renew_req = json!({
            "jsonrpc": "2.0",
            "id": 403,
            "method": "tools/call",
            "params": {
                "name": "ssl_certbot_renew",
                "arguments": {
                    "dry_run": true
                }
            }
        })
        .to_string();

        let renew_resp_str = dispatcher.handle_line(&renew_req).await.unwrap();
        let renew_resp: serde_json::Value = serde_json::from_str(&renew_resp_str).unwrap();
        assert_eq!(renew_resp["id"], 403);
        let renew_text = renew_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!renew_text.is_empty());

        // 4. tools/call: ssl_check_expiry with private key blocked by Guard
        let priv_key_req = json!({
            "jsonrpc": "2.0",
            "id": 404,
            "method": "tools/call",
            "params": {
                "name": "ssl_check_expiry",
                "arguments": {
                    "path": "/etc/ssl/private/server.key"
                }
            }
        })
        .to_string();

        let priv_resp_str = dispatcher.handle_line(&priv_key_req).await.unwrap();
        let priv_resp: serde_json::Value = serde_json::from_str(&priv_resp_str).unwrap();
        assert_eq!(priv_resp["id"], 404);
        assert_eq!(priv_resp["result"]["isError"], true);
        let priv_err = priv_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(priv_err.contains("Security Violation"));

        // 5. tools/call: ssl_check_expiry with domain injection blocked by Guard
        let dom_inj_req = json!({
            "jsonrpc": "2.0",
            "id": 405,
            "method": "tools/call",
            "params": {
                "name": "ssl_check_expiry",
                "arguments": {
                    "domain": "example.com; reboot"
                }
            }
        })
        .to_string();

        let dom_resp_str = dispatcher.handle_line(&dom_inj_req).await.unwrap();
        let dom_resp: serde_json::Value = serde_json::from_str(&dom_resp_str).unwrap();
        assert_eq!(dom_resp["id"], 405);
        assert_eq!(dom_resp["result"]["isError"], true);
        let dom_err = dom_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(dom_err.contains("Invalid characters") || dom_err.contains("shell metacharacters"));
    }

    #[tokio::test]
    async fn test_resources_protocol_and_subscriptions_lifecycle() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_mcp_res_test_{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        let allowed_dir = temp_dir.join("nginx");
        tokio::fs::create_dir_all(&allowed_dir).await.unwrap();

        let nginx_conf = allowed_dir.join("nginx.conf");
        tokio::fs::write(&nginx_conf, "events {} http { server {} }")
            .await
            .unwrap();

        let mut config = crate::config::Config::default();
        config.inspector.allowed_config_dirs = vec![allowed_dir.clone()];
        let dispatcher = McpDispatcher::with_config(config);

        // 1. initialize: verify resources capability declaration
        let init_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "1.0.0" }
            }
        })
        .to_string();

        let init_resp_str = dispatcher.handle_line(&init_req).await.unwrap();
        let init_resp: serde_json::Value = serde_json::from_str(&init_resp_str).unwrap();
        assert_eq!(init_resp["id"], 1);
        let capabilities = &init_resp["result"]["capabilities"];
        assert_eq!(capabilities["resources"]["subscribe"], true);
        assert_eq!(capabilities["resources"]["listChanged"], false);

        // 2. resources/list: verify supported resource enumeration
        let list_req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list"
        })
        .to_string();

        let list_resp_str = dispatcher.handle_line(&list_req).await.unwrap();
        let list_resp: serde_json::Value = serde_json::from_str(&list_resp_str).unwrap();
        assert_eq!(list_resp["id"], 2);
        let resources = list_resp["result"]["resources"].as_array().unwrap();
        assert!(resources.iter().any(|r| r["uri"] == "system://status"));
        assert!(
            resources
                .iter()
                .any(|r| r["uri"] == "config://nginx/nginx.conf")
        );
        assert!(resources.iter().any(|r| r["uri"] == "log://service/nginx"));

        // 3. resources/read: system://status
        let read_sys_req = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": {
                "uri": "system://status"
            }
        })
        .to_string();

        let read_sys_str = dispatcher.handle_line(&read_sys_req).await.unwrap();
        let read_sys_resp: serde_json::Value = serde_json::from_str(&read_sys_str).unwrap();
        assert_eq!(read_sys_resp["id"], 3);
        let contents = read_sys_resp["result"]["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], "system://status");
        assert_eq!(contents[0]["mimeType"], "application/json");
        let sys_status: serde_json::Value =
            serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert!(sys_status.get("hostname").is_some());

        // 4. resources/read: config://nginx/nginx.conf
        let read_cfg_req = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/read",
            "params": {
                "uri": "config://nginx/nginx.conf"
            }
        })
        .to_string();

        let read_cfg_str = dispatcher.handle_line(&read_cfg_req).await.unwrap();
        let read_cfg_resp: serde_json::Value = serde_json::from_str(&read_cfg_str).unwrap();
        assert_eq!(read_cfg_resp["id"], 4);
        let cfg_contents = read_cfg_resp["result"]["contents"].as_array().unwrap();
        assert_eq!(cfg_contents[0]["uri"], "config://nginx/nginx.conf");
        assert_eq!(cfg_contents[0]["text"], "events {} http { server {} }");

        // 5. resources/read: security protection against path traversal
        let bad_cfg_req = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/read",
            "params": {
                "uri": "config://nginx/../../etc/shadow"
            }
        })
        .to_string();

        let bad_cfg_str = dispatcher.handle_line(&bad_cfg_req).await.unwrap();
        let bad_cfg_resp: serde_json::Value = serde_json::from_str(&bad_cfg_str).unwrap();
        assert_eq!(bad_cfg_resp["id"], 5);
        assert!(bad_cfg_resp["error"].is_object());

        // 6. resources/subscribe & unsubscribe with session isolation
        let sub_session_a = "session_A";
        let sub_session_b = "session_B";

        let sub_req = json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "resources/subscribe",
            "params": {
                "uri": "system://status"
            }
        })
        .to_string();

        let sub_resp_a = dispatcher
            .handle_line_with_session(&sub_req, Some(sub_session_a))
            .await
            .unwrap();
        let sub_resp_val: serde_json::Value = serde_json::from_str(&sub_resp_a).unwrap();
        assert_eq!(sub_resp_val["id"], 6);
        assert!(sub_resp_val["result"].is_object());

        // Session A is subscribed, Session B is not
        assert!(
            dispatcher
                .subscription_manager
                .is_subscribed(sub_session_a, "system://status")
                .await
        );
        assert!(
            !dispatcher
                .subscription_manager
                .is_subscribed(sub_session_b, "system://status")
                .await
        );

        let subscribers = dispatcher
            .subscription_manager
            .get_subscribers("system://status")
            .await;
        assert_eq!(subscribers, vec![sub_session_a.to_string()]);

        // 7. resources/unsubscribe
        let unsub_req = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "resources/unsubscribe",
            "params": {
                "uri": "system://status"
            }
        })
        .to_string();

        let unsub_resp_a = dispatcher
            .handle_line_with_session(&unsub_req, Some(sub_session_a))
            .await
            .unwrap();
        let unsub_resp_val: serde_json::Value = serde_json::from_str(&unsub_resp_a).unwrap();
        assert_eq!(unsub_resp_val["id"], 7);

        assert!(
            !dispatcher
                .subscription_manager
                .is_subscribed(sub_session_a, "system://status")
                .await
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_stdio_server_initiated_notifications_stream() {
        let dispatcher = McpDispatcher::new();
        let event_bus = dispatcher.event_bus.clone();

        let (client_read, server_write) = tokio::io::duplex(8192);
        let (server_read, mut client_write) = tokio::io::duplex(8192);

        let server_handle =
            tokio::spawn(async move { dispatcher.run(server_read, server_write).await });

        let mut lines = BufReader::new(client_read).lines();

        // 1. Initialize
        let init_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "stdio-client", "version": "1.0.0" }
            }
        });
        client_write
            .write_all(format!("{init_req}\n").as_bytes())
            .await
            .unwrap();

        let init_resp = lines.next_line().await.unwrap().expect("init response");
        let init_val: serde_json::Value = serde_json::from_str(&init_resp).unwrap();
        assert_eq!(init_val["id"], 1);

        // Ack
        let ack = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        client_write
            .write_all(format!("{ack}\n").as_bytes())
            .await
            .unwrap();

        // 2. Subscribe to system://status
        let sub_req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/subscribe",
            "params": { "uri": "system://status" }
        });
        client_write
            .write_all(format!("{sub_req}\n").as_bytes())
            .await
            .unwrap();

        let sub_resp = lines.next_line().await.unwrap().expect("sub response");
        let sub_val: serde_json::Value = serde_json::from_str(&sub_resp).unwrap();
        assert_eq!(sub_val["id"], 2);

        // 3. Emit ResourceUpdated for system://status -> should be delivered to stdio without ID
        event_bus.publish_immediate(crate::events::ServerEvent::ResourceUpdated {
            uri: "system://status".to_string(),
        });

        let notif_line = lines.next_line().await.unwrap().expect("notification line");
        let notif_val: serde_json::Value = serde_json::from_str(&notif_line).unwrap();

        // Crucial requirement: notification has NO id field
        assert!(notif_val.get("id").is_none());
        assert_eq!(notif_val["method"], "notifications/resources/updated");
        assert_eq!(notif_val["params"]["uri"], "system://status");

        // 4. Emit TaskCompleted event -> broadcast should be delivered without ID
        event_bus.publish_immediate(crate::events::ServerEvent::TaskCompleted {
            task_id: "bg-task-stdio-1".to_string(),
            status: crate::tasks::TaskStatus::Success,
        });

        let task_notif_line = lines
            .next_line()
            .await
            .unwrap()
            .expect("task notification line");
        let task_notif: serde_json::Value = serde_json::from_str(&task_notif_line).unwrap();

        assert!(task_notif.get("id").is_none());
        assert_eq!(task_notif["method"], "notifications/tasks/completed");
        assert_eq!(task_notif["params"]["taskId"], "bg-task-stdio-1");

        // 5. Clean teardown: close client write, server loop finishes cleanly
        drop(client_write);
        let server_res = server_handle.await.unwrap();
        assert!(server_res.is_ok());
    }
}
