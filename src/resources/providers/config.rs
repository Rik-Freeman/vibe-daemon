//! Configuration Resource Provider (`config://` scheme).
//! Safely serves authorized web server and daemon configuration files under the `config://` scheme,
//! enforcing strict path traversal guards, allowed directories quotas, and size limits.

use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::debug;

use crate::config::Config;
use crate::guard::fs_guard::{check_file_read_safety_with_config, normalize_path};
use crate::mcp::protocol::{Resource, ResourceContents, ResourcePage};
use crate::resources::registry::{ResourceError, ResourceProvider};

/// Resource provider serving configuration files under the `config://` URI scheme.
pub struct ConfigResourceProvider {
    config: Arc<Config>,
}

impl ConfigResourceProvider {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    /// Resolves an incoming `config://` URI to a strictly verified local path within allowed directories.
    fn resolve_uri_to_path(&self, uri: &str) -> Result<(PathBuf, PathBuf), ResourceError> {
        let stripped = uri.strip_prefix("config://").ok_or_else(|| {
            ResourceError::InvalidUri(format!("URI '{uri}' must start with 'config://'"))
        })?;

        let clean_relative = stripped.trim_start_matches('/');
        if clean_relative.is_empty() {
            return Err(ResourceError::InvalidUri(
                "Configuration path cannot be empty".to_string(),
            ));
        }

        // Direct check for directory traversal tokens
        if clean_relative.contains("..")
            || clean_relative.contains("%2e")
            || clean_relative.contains('\0')
        {
            return Err(ResourceError::AccessDenied(
                "Path traversal tokens ('..', null bytes) are prohibited".to_string(),
            ));
        }

        let allowed_dirs = &self.config.inspector.allowed_config_dirs;
        if allowed_dirs.is_empty() {
            return Err(ResourceError::AccessDenied(
                "No configuration directories are authorized for inspection".to_string(),
            ));
        }

        // Attempt matching against allowed directories
        // Example: uri "config://nginx/nginx.conf" -> matches allowed directory ending in "nginx" with subpath "nginx.conf",
        // or matches root of allowed directory if clean_relative starts with directory name.
        for allowed in allowed_dirs {
            let normalized_allowed = match normalize_path(allowed) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let dir_name = normalized_allowed
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();

            let target_subpath =
                if let Some(sub) = clean_relative.strip_prefix(&format!("{dir_name}/")) {
                    sub
                } else if clean_relative == dir_name {
                    ""
                } else {
                    clean_relative
                };

            let candidate = normalized_allowed.join(target_subpath);
            let normalized_candidate = match normalize_path(&candidate) {
                Ok(p) => p,
                Err(err) => {
                    return Err(ResourceError::AccessDenied(format!(
                        "Path normalization error: {err}"
                    )));
                }
            };

            // Verify canonical prefix containment
            if normalized_candidate.starts_with(&normalized_allowed) {
                return Ok((normalized_allowed, normalized_candidate));
            }
        }

        Err(ResourceError::AccessDenied(format!(
            "Path '{clean_relative}' is outside of authorized configuration directories"
        )))
    }
}

#[async_trait]
impl ResourceProvider for ConfigResourceProvider {
    fn schemes(&self) -> &[&str] {
        &["config"]
    }

    async fn list(&self, _cursor: Option<&str>) -> Result<ResourcePage, ResourceError> {
        let mut resources = Vec::new();
        let allowed_dirs = &self.config.inspector.allowed_config_dirs;

        for dir in allowed_dirs {
            if !dir.exists() || !dir.is_dir() {
                continue;
            }

            let dir_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("config");

            // Scan directory entries (up to 2 levels deep)
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if fname.ends_with(".conf")
                            || fname.ends_with(".cfg")
                            || fname.ends_with(".toml")
                            || fname.ends_with(".yaml")
                            || fname.ends_with(".yml")
                        {
                            let uri = format!("config://{dir_name}/{fname}");
                            resources.push(Resource {
                                uri,
                                name: format!("Configuration: {fname}"),
                                description: Some(format!(
                                    "Configuration file at {}",
                                    path.display()
                                )),
                                mime_type: Some("text/plain".to_string()),
                            });
                        }
                    }
                }
            }
        }

        // If no physical files were found (e.g. non-Linux / test environment), provide standard default descriptors
        if resources.is_empty() {
            resources.push(Resource {
                uri: "config://nginx/nginx.conf".to_string(),
                name: "Nginx Master Configuration".to_string(),
                description: Some(
                    "Primary Nginx configuration file (/etc/nginx/nginx.conf)".to_string(),
                ),
                mime_type: Some("text/plain".to_string()),
            });
        }

        debug!(count = resources.len(), "Config provider listed resources");
        Ok(ResourcePage {
            resources,
            next_cursor: None,
        })
    }

    async fn read(&self, uri: &str) -> Result<ResourceContents, ResourceError> {
        let (_allowed_root, target_path) = self.resolve_uri_to_path(uri)?;

        // Enforce fs_guard safety verification (blocks /etc/shadow, private keys, sudoers, etc.)
        check_file_read_safety_with_config(&target_path, &self.config.security)
            .map_err(|e| ResourceError::AccessDenied(format!("Security Violation: {e}")))?;

        if !target_path.exists() {
            return Err(ResourceError::NotFound(format!(
                "Configuration file not found: {}",
                target_path.display()
            )));
        }

        if !target_path.is_file() {
            return Err(ResourceError::AccessDenied(format!(
                "Path is not a regular file: {}",
                target_path.display()
            )));
        }

        // Check file size limits
        let metadata = tokio::fs::metadata(&target_path)
            .await
            .map_err(|e| ResourceError::ExecutionError(format!("Failed to read metadata: {e}")))?;

        let max_bytes = self.config.tasks.output_limit_bytes as u64;
        if metadata.len() > max_bytes {
            return Err(ResourceError::LimitExceeded(format!(
                "Configuration file size ({} bytes) exceeds security output limit ({} bytes)",
                metadata.len(),
                max_bytes
            )));
        }

        let content = tokio::fs::read_to_string(&target_path).await.map_err(|e| {
            ResourceError::ExecutionError(format!("Failed to read configuration: {e}"))
        })?;

        Ok(ResourceContents::text(
            uri,
            Some("text/plain".to_string()),
            content,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_config_provider_security_and_traversal() {
        let temp_dir = std::env::temp_dir().join("vibe_test_config_provider");
        let _ = std::fs::create_dir_all(&temp_dir);
        let test_file = temp_dir.join("test.conf");
        std::fs::write(&test_file, "server { listen 80; }").unwrap();

        let mut config = Config::default();
        config.inspector.allowed_config_dirs = vec![temp_dir.clone()];
        let provider = ConfigResourceProvider::new(Arc::new(config));

        // 1. List
        let list_res = provider.list(None).await.unwrap();
        assert!(!list_res.resources.is_empty());

        // 2. Safe read
        let uri = format!(
            "config://{}/test.conf",
            temp_dir.file_name().unwrap().to_str().unwrap()
        );
        let read_res = provider.read(&uri).await.unwrap();
        match read_res {
            ResourceContents::Text { text, .. } => assert_eq!(text, "server { listen 80; }"),
            _ => panic!("Expected text"),
        }

        // 3. Path traversal blocked
        let bad_uri = format!(
            "config://{}/../../etc/shadow",
            temp_dir.file_name().unwrap().to_str().unwrap()
        );
        let err = provider.read(&bad_uri).await.unwrap_err();
        assert!(matches!(err, ResourceError::AccessDenied(_)));

        // 4. Non-existent file
        let not_found_uri = format!(
            "config://{}/non_existent.conf",
            temp_dir.file_name().unwrap().to_str().unwrap()
        );
        let err2 = provider.read(&not_found_uri).await.unwrap_err();
        assert!(matches!(err2, ResourceError::NotFound(_)));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
