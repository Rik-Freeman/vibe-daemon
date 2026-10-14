//! System Resource Provider (`system://` scheme).
//! Exposes real-time system metrics, inspector status, and host summary as MCP resources.

use async_trait::async_trait;
use std::sync::Arc;

use crate::config::Config;
use crate::mcp::protocol::{Resource, ResourceContents, ResourcePage};
use crate::resources::registry::{ResourceError, ResourceProvider};

use serde::{Deserialize, Serialize};

/// Report of active system ports and established TCP connections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemPortsResource {
    pub listening_ports: Vec<crate::inspector::ListeningPort>,
    pub listening_count: usize,
    pub established_connections: usize,
}

/// Report of configured key system services and their live statuses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemServicesResource {
    pub key_services: Vec<String>,
    pub services: Vec<crate::inspector::ServiceStatus>,
}

/// Helper to collect system ports and established connections.
pub async fn collect_ports_resource() -> SystemPortsResource {
    let listening_ports = crate::inspector::collect_listening_ports().await;
    let listening_count = listening_ports.len();
    let mut established_connections = 0;

    if let Ok(tcp) = tokio::fs::read_to_string("/proc/net/tcp").await {
        established_connections +=
            crate::tools::monitoring::count_established_tcp_connections(&tcp);
    }
    if let Ok(tcp6) = tokio::fs::read_to_string("/proc/net/tcp6").await {
        established_connections +=
            crate::tools::monitoring::count_established_tcp_connections(&tcp6);
    }

    #[cfg(windows)]
    if established_connections == 0 {
        let ps_cmd = "(Get-NetTCPConnection -State Established).Count";
        let mut ps = tokio::process::Command::new("powershell");
        ps.args(["-Command", ps_cmd]);
        if let Some(s) = crate::executor::execute_quick_process(ps, 3).await
            && let Some(first) = s.lines().next()
            && let Ok(c) = first.trim().parse::<usize>()
        {
            established_connections = c;
        }
    }

    SystemPortsResource {
        listening_ports,
        listening_count,
        established_connections,
    }
}

/// Helper to collect configured key system services statuses.
pub async fn collect_services_resource(key_services: &[String]) -> SystemServicesResource {
    let mut services = Vec::new();
    for svc in key_services {
        services.push(crate::inspector::check_service_status(svc).await);
    }

    SystemServicesResource {
        key_services: key_services.to_vec(),
        services,
    }
}

/// Resource provider serving dynamic system metrics under the `system://` URI scheme.
pub struct SystemResourceProvider {
    config: Arc<Config>,
}

impl SystemResourceProvider {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    fn verify_output_limit(&self, json_text: &str) -> Result<(), ResourceError> {
        let max_bytes = self.config.tasks.output_limit_bytes;
        if json_text.len() > max_bytes {
            return Err(ResourceError::LimitExceeded(format!(
                "Output size ({} bytes) exceeds security output limit ({} bytes)",
                json_text.len(),
                max_bytes
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl ResourceProvider for SystemResourceProvider {
    fn schemes(&self) -> &[&str] {
        &["system"]
    }

    async fn list(&self, _cursor: Option<&str>) -> Result<ResourcePage, ResourceError> {
        let resources = vec![
            Resource {
                uri: "system://status".to_string(),
                name: "System Status".to_string(),
                description: Some(
                    "Real-time host system status, uptime, memory, services and ports summary"
                        .to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: "system://ports".to_string(),
                name: "System Ports & Connections".to_string(),
                description: Some(
                    "Active listening network ports and established TCP connections on the host"
                        .to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: "system://services".to_string(),
                name: "System Services Status".to_string(),
                description: Some(
                    "Operational status of configured key system services and daemons".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
        ];

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

                self.verify_output_limit(&json_text)?;

                Ok(ResourceContents::text(
                    "system://status",
                    Some("application/json".to_string()),
                    json_text,
                ))
            }
            "system://ports" => {
                let ports_report = collect_ports_resource().await;
                let json_text = serde_json::to_string_pretty(&ports_report).map_err(|e| {
                    ResourceError::ExecutionError(format!("Failed to serialize system ports: {e}"))
                })?;

                self.verify_output_limit(&json_text)?;

                Ok(ResourceContents::text(
                    "system://ports",
                    Some("application/json".to_string()),
                    json_text,
                ))
            }
            "system://services" => {
                let services_report =
                    collect_services_resource(&self.config.inspector.key_services).await;
                let json_text = serde_json::to_string_pretty(&services_report).map_err(|e| {
                    ResourceError::ExecutionError(format!(
                        "Failed to serialize system services: {e}"
                    ))
                })?;

                self.verify_output_limit(&json_text)?;

                Ok(ResourceContents::text(
                    "system://services",
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

        // 1. List
        let list_res = provider.list(None).await.unwrap();
        assert_eq!(list_res.resources.len(), 3);
        assert_eq!(list_res.resources[0].uri, "system://status");
        assert_eq!(list_res.resources[1].uri, "system://ports");
        assert_eq!(list_res.resources[2].uri, "system://services");

        // 2. Read system://status
        let status_res = provider.read("system://status").await.unwrap();
        match status_res {
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

        // 3. Read system://ports
        let ports_res = provider.read("system://ports").await.unwrap();
        match ports_res {
            ResourceContents::Text {
                uri,
                mime_type,
                text,
            } => {
                assert_eq!(uri, "system://ports");
                assert_eq!(mime_type, Some("application/json".to_string()));
                assert!(text.contains("listening_ports"));
                assert!(text.contains("established_connections"));
            }
            _ => panic!("Expected text resource contents"),
        }

        // 4. Read system://services
        let services_res = provider.read("system://services").await.unwrap();
        match services_res {
            ResourceContents::Text {
                uri,
                mime_type,
                text,
            } => {
                assert_eq!(uri, "system://services");
                assert_eq!(mime_type, Some("application/json".to_string()));
                assert!(text.contains("key_services"));
                assert!(text.contains("services"));
            }
            _ => panic!("Expected text resource contents"),
        }

        // 5. Read unknown URI
        let unknown_res = provider.read("system://invalid").await;
        assert!(matches!(unknown_res, Err(ResourceError::NotFound(_))));
    }
}
