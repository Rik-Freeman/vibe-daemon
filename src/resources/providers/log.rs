//! Log Resource Provider (`log://` scheme).
//! Provides safe access to systemd and service log tails under the `log://service/...` URI scheme,
//! enforcing strict service identifier validation, command injection guards, and bounded limits.

use async_trait::async_trait;
use std::sync::Arc;

use crate::config::Config;
use crate::guard::check_service_log_query_safety_with_config;
use crate::mcp::protocol::{Resource, ResourceContents, ResourcePage};
use crate::resources::registry::{ResourceError, ResourceProvider};

/// Resource provider serving service log streams under the `log://` URI scheme.
pub struct LogResourceProvider {
    config: Arc<Config>,
}

impl LogResourceProvider {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ResourceProvider for LogResourceProvider {
    fn schemes(&self) -> &[&str] {
        &["log"]
    }

    async fn list(&self, _cursor: Option<&str>) -> Result<ResourcePage, ResourceError> {
        let mut services = vec![
            "nginx".to_string(),
            "sshd".to_string(),
            "systemd".to_string(),
            "vibe-daemon".to_string(),
        ];

        for key_svc in &self.config.inspector.key_services {
            if !services.contains(key_svc) {
                services.push(key_svc.clone());
            }
        }

        let resources = services
            .into_iter()
            .map(|svc| Resource {
                uri: format!("log://service/{svc}"),
                name: format!("Service Logs: {svc}"),
                description: Some(format!("Recent systemd service journal logs for '{svc}'")),
                mime_type: Some("text/plain".to_string()),
            })
            .collect();

        Ok(ResourcePage {
            resources,
            next_cursor: None,
        })
    }

    async fn read(&self, uri: &str) -> Result<ResourceContents, ResourceError> {
        let stripped = uri.strip_prefix("log://service/").ok_or_else(|| {
            ResourceError::InvalidUri(format!(
                "Log resource URI '{uri}' must start with 'log://service/<service_name>'"
            ))
        })?;

        let clean_service = stripped.trim();
        if clean_service.is_empty() {
            return Err(ResourceError::InvalidUri(
                "Service name cannot be empty".to_string(),
            ));
        }

        // Security validation against shell injection and malicious service names
        check_service_log_query_safety_with_config(clean_service, &self.config.security)
            .map_err(|e| ResourceError::AccessDenied(format!("Security Violation: {e}")))?;

        // Retrieve bounded logs compressed via Smart Log Engine
        let logs = crate::tools::monitoring::tail_service_logs_with_config(
            clean_service,
            Some(100),
            None,
            None,
            &self.config.security,
        )
        .await
        .map_err(ResourceError::ExecutionError)?;

        let max_bytes = self.config.tasks.output_limit_bytes;
        if logs.len() > max_bytes {
            return Err(ResourceError::LimitExceeded(format!(
                "Service logs size ({} bytes) exceeds output limit ({} bytes)",
                logs.len(),
                max_bytes
            )));
        }

        Ok(ResourceContents::text(
            uri,
            Some("text/plain".to_string()),
            logs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_log_provider_list_and_injection_guard() {
        let config = Arc::new(Config::default());
        let provider = LogResourceProvider::new(config);

        let list_res = provider.list(None).await.unwrap();
        assert!(
            list_res
                .resources
                .iter()
                .any(|r| r.uri == "log://service/nginx")
        );

        // Injection attempt blocked
        let bad_uri = "log://service/nginx; rm -rf /";
        let err = provider.read(bad_uri).await.unwrap_err();
        assert!(matches!(err, ResourceError::AccessDenied(_)));

        // Safe service read
        let safe_res = provider.read("log://service/nginx").await.unwrap();
        match safe_res {
            ResourceContents::Text { uri, text, .. } => {
                assert_eq!(uri, "log://service/nginx");
                assert!(text.contains("nginx"));
            }
            _ => panic!("Expected text"),
        }
    }
}
