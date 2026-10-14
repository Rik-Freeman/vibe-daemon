//! Dynamic Plugin and Tool Registry Subsystem.
//! Defines the `McpTool` trait, the execution context `ToolContext`, and the central `ToolRegistry`.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

use crate::config::Config;
use crate::mcp::protocol::{CallToolResult, Tool};

// -----------------------------------------------------------------------------
// Tool Context
// -----------------------------------------------------------------------------

/// Shared execution context passed to all `McpTool` plugin implementations.
/// Provides controlled access to daemon configuration, security settings,
/// audit logging, rate limiting, and background task management.
#[derive(Clone)]
pub struct ToolContext {
    pub config: Arc<Config>,
    pub audit_logger: Arc<crate::audit::AuditLogger>,
    pub rate_limiter: Arc<crate::rate_limiter::RateLimiter>,
    pub task_manager: Arc<crate::tasks::TaskManager>,
    pub connected_client: Option<String>,
}

impl ToolContext {
    pub fn new(
        config: Arc<Config>,
        audit_logger: Arc<crate::audit::AuditLogger>,
        rate_limiter: Arc<crate::rate_limiter::RateLimiter>,
        task_manager: Arc<crate::tasks::TaskManager>,
        connected_client: Option<String>,
    ) -> Self {
        Self {
            config,
            audit_logger,
            rate_limiter,
            task_manager,
            connected_client,
        }
    }

    /// Helper constructor with default dependencies, useful for unit tests.
    pub fn default_test_context() -> Self {
        let config = Arc::new(Config::default());
        let audit_logger =
            Arc::new(crate::audit::AuditLogger::new(None).expect("No path audit logger"));
        let rate_limiter = Arc::new(crate::rate_limiter::RateLimiter::from_config(
            &config.security,
        ));
        let task_manager = Arc::new(crate::tasks::TaskManager::new());
        Self {
            config,
            audit_logger,
            rate_limiter,
            task_manager,
            connected_client: None,
        }
    }
}

// -----------------------------------------------------------------------------
// McpTool Trait
// -----------------------------------------------------------------------------

/// Asynchronous trait implemented by all MCP tools/plugins.
#[async_trait]
pub trait McpTool: Send + Sync {
    /// Unique identifier name of the tool (e.g. "docker_ps", "read_file").
    fn name(&self) -> &str;

    /// Human-readable description explaining what the tool does.
    fn description(&self) -> &str;

    /// JSON Schema describing required and optional parameters.
    fn input_schema(&self) -> serde_json::Value;

    /// Executes the tool with the given arguments and execution context.
    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String>;
}

// -----------------------------------------------------------------------------
// Tool Registry
// -----------------------------------------------------------------------------

/// Central registry managing all available `McpTool` instances.
/// Supports dynamic registration, introspection (`tools/list`), and execution routing (`tools/call`).
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn McpTool>>,
    order: Vec<String>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ToolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolRegistry")
            .field("tools", &self.order)
            .finish()
    }
}

impl ToolRegistry {
    /// Creates an empty tool registry.
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            order: Vec::new(),
        }
    }

    /// Registers a tool implementing `McpTool`.
    pub fn register(&mut self, tool: Arc<dyn McpTool>) {
        let name = tool.name().to_string();
        debug!(tool = %name, "Registering MCP tool plugin");
        if !self.tools.contains_key(&name) {
            self.order.push(name.clone());
        }
        self.tools.insert(name, tool);
    }

    /// Convenience helper to register a tool from a concrete value.
    pub fn register_tool(&mut self, tool: impl McpTool + 'static) {
        self.register(Arc::new(tool));
    }

    /// Retrieves a registered tool by its name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn McpTool>> {
        self.tools.get(name).cloned()
    }

    /// Checks if a tool with the given name is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Total count of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Returns true if no tools are registered.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Generates the list of `Tool` definitions preserving registration order for `tools/list`.
    pub fn list_tools(&self) -> Vec<Tool> {
        self.order
            .iter()
            .filter_map(|name| self.tools.get(name))
            .map(|tool| Tool {
                name: tool.name().to_string(),
                description: Some(tool.description().to_string()),
                input_schema: tool.input_schema(),
            })
            .collect()
    }

    /// Initializes a default registry with all 33 built-in tools.
    pub fn default_registry() -> Self {
        let mut registry = Self::new();
        crate::tools::system::register_system_tools(&mut registry);
        crate::tools::file_ops::register_file_ops_tools(&mut registry);
        crate::tools::config_writer::register_config_writer_tools(&mut registry);
        crate::tools::monitoring::register_monitoring_tools(&mut registry);
        crate::tasks::register_task_tools(&mut registry);
        crate::tools::docker::register_docker_tools(&mut registry);
        crate::tools::webserver::register_webserver_tools(&mut registry);
        crate::tools::ssl::register_ssl_tools(&mut registry);
        registry
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoTestTool;

    #[async_trait]
    impl McpTool for EchoTestTool {
        fn name(&self) -> &str {
            "echo_test"
        }

        fn description(&self) -> &str {
            "Echoes input text back for unit testing"
        }

        fn input_schema(&self) -> serde_json::Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "msg": { "type": "string" }
                },
                "required": ["msg"]
            })
        }

        async fn execute(
            &self,
            args: serde_json::Value,
            _ctx: &ToolContext,
        ) -> Result<CallToolResult, String> {
            let msg = args.get("msg").and_then(|m| m.as_str()).unwrap_or("");
            Ok(CallToolResult::text(format!("echo:{msg}")))
        }
    }

    #[tokio::test]
    async fn test_tool_registry_registration_and_execution() {
        let mut registry = ToolRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.register_tool(EchoTestTool);
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(registry.contains("echo_test"));

        let tool = registry.get("echo_test").expect("Tool should be found");
        assert_eq!(tool.name(), "echo_test");
        assert_eq!(
            tool.description(),
            "Echoes input text back for unit testing"
        );

        let ctx = ToolContext::default_test_context();
        let res = tool
            .execute(serde_json::json!({ "msg": "hello_vibe" }), &ctx)
            .await
            .expect("Execution should succeed");

        assert!(res.is_error.is_none());
        match &res.content[0] {
            crate::mcp::protocol::ToolContent::Text { text } => {
                assert_eq!(text, "echo:hello_vibe");
            }
        }

        let list = registry.list_tools();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "echo_test");
    }

    #[test]
    fn test_tool_registry_unknown_tool() {
        let registry = ToolRegistry::new();
        assert!(registry.get("non_existent").is_none());
        assert!(!registry.contains("non_existent"));
    }
}
