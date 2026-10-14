//! System Resource Provider (`system://` scheme).
//! Exposes real-time system metrics, inspector status, and host summary as MCP resources.

use async_trait::async_trait;
use std::sync::Arc;

use crate::config::Config;
use crate::mcp::protocol::{Resource, ResourceContents, ResourcePage};
use crate::resources::registry::{ResourceError, ResourceProvider};

/// Resource provider serving dynamic system metrics under the `system://` URI scheme.
pub struct SystemResourceProvider {
    config: Arc<Config>,
}

impl SystemResourceProvider {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ResourceProvider for SystemResourceProvider {
    fn schemes(&self) -> &[&str] {
        &["system"]
    }

    async fn list(&self, _cursor: Option<&str>) -> Result<ResourcePage, ResourceError> {
        let resources = vec![Resource {
            uri: "system://status".to_string(),
            name: "System Status".to_string(),
            description: Some(
                "Real-time host system status, uptime, memory, services and ports summary"
                    .to_string(),
            ),
            mime_type: Some("application/json".to_string()),
        }];

        Ok(ResourcePage {
            resources,
            next_cursor: None,
        })
    }

    async fn read(&self, uri: &str) -> Result<ResourceContents, ResourceError> {
        match uri {
            "system://status" => {
                let status =
                    crate::inspector::collect_system_status_with_config(&self.config.inspector)
                        .await;
                let json_text = serde_json::to_string_pretty(&status).map_err(|e| {
                    ResourceError::ExecutionError(format!("Failed to serialize system status: {e}"))
                })?;

                let max_bytes = self.config.tasks.output_limit_bytes;
                if json_text.len() > max_bytes {
                    return Err(ResourceError::LimitExceeded(format!(
                        "System status output ({} bytes) exceeds security output limit ({} bytes)",
                        json_text.len(),
                        max_bytes
                    )));
                }

                Ok(ResourceContents::text(
                    "system://status",
                    Some("application/json".to_string()),
                    json_text,
                ))
            }
            _ => Err(ResourceError::NotFound(format!(
                "Unknown system resource URI '{uri}'"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_system_provider_list_and_read() {
        let config = Arc::new(Config::default());
        let provider = SystemResourceProvider::new(config);

        let list_res = provider.list(None).await.unwrap();
        assert_eq!(list_res.resources.len(), 1);
        assert_eq!(list_res.resources[0].uri, "system://status");

        let read_res = provider.read("system://status").await.unwrap();
        match read_res {
            ResourceContents::Text {
                uri,
                mime_type,
                text,
            } => {
                assert_eq!(uri, "system://status");
                assert_eq!(mime_type, Some("application/json".to_string()));
                assert!(text.contains("hostname"));
            }
            _ => panic!("Expected text resource contents"),
        }

        let unknown_res = provider.read("system://invalid").await;
        assert!(matches!(unknown_res, Err(ResourceError::NotFound(_))));
    }
}
