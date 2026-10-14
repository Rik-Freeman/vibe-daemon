//! Provider-oriented MCP Resource Registry subsystem.
//! Defines the `ResourceProvider` trait, `ResourceError`, and the central `ResourceRegistry`.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

use crate::config::Config;
use crate::mcp::protocol::{ResourceContents, ResourcePage};

/// Error types returned by resource providers during listing or reading operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    NotFound(String),
    AccessDenied(String),
    InvalidUri(String),
    ExecutionError(String),
    LimitExceeded(String),
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "Resource not found: {msg}"),
            Self::AccessDenied(msg) => write!(f, "Access denied: {msg}"),
            Self::InvalidUri(msg) => write!(f, "Invalid resource URI: {msg}"),
            Self::ExecutionError(msg) => write!(f, "Execution error: {msg}"),
            Self::LimitExceeded(msg) => write!(f, "Limit exceeded: {msg}"),
        }
    }
}

impl std::error::Error for ResourceError {}

/// Asynchronous trait implemented by all MCP resource providers.
#[async_trait]
pub trait ResourceProvider: Send + Sync {
    /// URI schemes handled by this provider (e.g. `["system"]`, `["config"]`, `["log"]`).
    fn schemes(&self) -> &[&str];

    /// Returns a paginated list of available resources.
    async fn list(&self, cursor: Option<&str>) -> Result<ResourcePage, ResourceError>;

    /// Reads the contents of a specific resource by URI.
    async fn read(&self, uri: &str) -> Result<ResourceContents, ResourceError>;
}

/// Central registry managing all registered `ResourceProvider` instances and dispatching URI queries.
#[derive(Clone, Default)]
pub struct ResourceRegistry {
    providers: Vec<Arc<dyn ResourceProvider>>,
    by_scheme: HashMap<String, Arc<dyn ResourceProvider>>,
}

impl std::fmt::Debug for ResourceRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceRegistry")
            .field("providers_count", &self.providers.len())
            .field("schemes", &self.by_scheme.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ResourceRegistry {
    /// Create an empty resource registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a resource provider instance.
    pub fn register_provider<P: ResourceProvider + 'static>(&mut self, provider: P) {
        let arc = Arc::new(provider);
        self.register_arc(arc);
    }

    /// Register an Arc-wrapped resource provider.
    pub fn register_arc(&mut self, provider: Arc<dyn ResourceProvider>) {
        for scheme in provider.schemes() {
            self.by_scheme
                .insert(scheme.to_lowercase(), provider.clone());
        }
        self.providers.push(provider);
    }

    /// Returns all resources aggregated across registered providers.
    pub async fn list(&self, cursor: Option<&str>) -> Result<ResourcePage, ResourceError> {
        let mut all_resources = Vec::new();
        for provider in &self.providers {
            let page = provider.list(cursor).await?;
            all_resources.extend(page.resources);
        }

        debug!(
            count = all_resources.len(),
            "Aggregated resource list returned"
        );
        Ok(ResourcePage {
            resources: all_resources,
            next_cursor: None,
        })
    }

    /// Reads the specified resource URI by routing to the appropriate scheme provider.
    pub async fn read(&self, uri: &str) -> Result<ResourceContents, ResourceError> {
        let clean_uri = uri.trim();
        if clean_uri.is_empty() {
            return Err(ResourceError::InvalidUri(
                "Resource URI cannot be empty".to_string(),
            ));
        }

        let scheme = match clean_uri.split_once("://") {
            Some((s, _)) => s.to_lowercase(),
            None => {
                return Err(ResourceError::InvalidUri(format!(
                    "Missing scheme delimiter '://' in URI '{clean_uri}'"
                )));
            }
        };

        let provider = self.by_scheme.get(&scheme).ok_or_else(|| {
            ResourceError::NotFound(format!(
                "No resource provider registered for scheme '{scheme}'"
            ))
        })?;

        provider.read(clean_uri).await
    }

    /// Instantiates the default registry with built-in system, config, and log providers.
    pub fn default_registry(config: Arc<Config>) -> Self {
        let mut registry = Self::new();
        registry.register_provider(super::providers::system::SystemResourceProvider::new(
            config.clone(),
        ));
        registry.register_provider(super::providers::config::ConfigResourceProvider::new(
            config.clone(),
        ));
        registry.register_provider(super::providers::log::LogResourceProvider::new(config));
        registry
    }
}
