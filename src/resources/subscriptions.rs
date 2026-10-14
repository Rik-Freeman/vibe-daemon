//! Session-level MCP Resource Subscriptions subsystem.
//! Manages client session subscriptions (`session_id -> set(resource_uri)`)
//! and guarantees isolation and disconnect cleanup.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Manages resource subscriptions on a per-client session basis.
#[derive(Debug, Default, Clone)]
pub struct SubscriptionManager {
    sessions: Arc<RwLock<HashMap<String, HashSet<String>>>>,
}

impl SubscriptionManager {
    /// Creates a new subscription manager.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribes a client session to the given resource URI.
    pub async fn subscribe(&self, session_id: &str, uri: &str) -> Result<(), String> {
        let clean_uri = uri.trim();
        if clean_uri.is_empty() {
            return Err("Resource URI cannot be empty".to_string());
        }

        let mut lock = self.sessions.write().await;
        let set = lock.entry(session_id.to_string()).or_default();
        set.insert(clean_uri.to_string());
        info!(session = %session_id, uri = %clean_uri, "Client subscribed to resource");
        Ok(())
    }

    /// Unsubscribes a client session from the given resource URI.
    pub async fn unsubscribe(&self, session_id: &str, uri: &str) -> Result<bool, String> {
        let clean_uri = uri.trim();
        let mut lock = self.sessions.write().await;
        if let Some(set) = lock.get_mut(session_id) {
            let removed = set.remove(clean_uri);
            if removed {
                info!(session = %session_id, uri = %clean_uri, "Client unsubscribed from resource");
            }
            Ok(removed)
        } else {
            Ok(false)
        }
    }

    /// Returns `true` if the given session is actively subscribed to the resource URI.
    pub async fn is_subscribed(&self, session_id: &str, uri: &str) -> bool {
        let lock = self.sessions.read().await;
        lock.get(session_id)
            .map(|set| set.contains(uri))
            .unwrap_or(false)
    }

    /// Retrieves all active resource URI subscriptions for a specific session.
    pub async fn session_subscriptions(&self, session_id: &str) -> Vec<String> {
        let lock = self.sessions.read().await;
        lock.get(session_id)
            .map(|set| {
                let mut v: Vec<String> = set.iter().cloned().collect();
                v.sort();
                v
            })
            .unwrap_or_default()
    }

    /// Retrieves all session IDs subscribed to a given resource URI.
    pub async fn get_subscribers(&self, uri: &str) -> Vec<String> {
        let lock = self.sessions.read().await;
        let mut subscribers = Vec::new();
        for (session_id, uris) in lock.iter() {
            if uris.contains(uri) {
                subscribers.push(session_id.clone());
            }
        }
        subscribers.sort();
        subscribers
    }

    /// Completely removes a session and purges all of its resource subscriptions upon disconnect.
    pub async fn cleanup_session(&self, session_id: &str) -> usize {
        let mut lock = self.sessions.write().await;
        if let Some(removed_set) = lock.remove(session_id) {
            let count = removed_set.len();
            debug!(
                session = %session_id,
                removed_subscriptions = count,
                "Cleaned up session subscriptions upon disconnect"
            );
            count
        } else {
            0
        }
    }

    /// Returns the number of distinct sessions currently having active subscriptions.
    pub async fn active_sessions_count(&self) -> usize {
        let lock = self.sessions.read().await;
        lock.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_subscription_lifecycle() {
        let mgr = SubscriptionManager::new();

        assert!(!mgr.is_subscribed("sess_1", "system://status").await);
        mgr.subscribe("sess_1", "system://status").await.unwrap();
        assert!(mgr.is_subscribed("sess_1", "system://status").await);

        // Session 2 isolation
        assert!(!mgr.is_subscribed("sess_2", "system://status").await);
        mgr.subscribe("sess_2", "config://nginx/nginx.conf")
            .await
            .unwrap();

        let subs1 = mgr.session_subscriptions("sess_1").await;
        assert_eq!(subs1, vec!["system://status"]);

        let subs2 = mgr.session_subscriptions("sess_2").await;
        assert_eq!(subs2, vec!["config://nginx/nginx.conf"]);

        // Subscribers for uri
        let subscribers = mgr.get_subscribers("system://status").await;
        assert_eq!(subscribers, vec!["sess_1"]);

        // Unsubscribe
        let removed = mgr.unsubscribe("sess_1", "system://status").await.unwrap();
        assert!(removed);
        assert!(!mgr.is_subscribed("sess_1", "system://status").await);

        // Disconnect cleanup
        assert_eq!(mgr.active_sessions_count().await, 2); // sess_1 has empty set, sess_2 has 1
        mgr.cleanup_session("sess_2").await;
        assert!(
            !mgr.is_subscribed("sess_2", "config://nginx/nginx.conf")
                .await
        );
    }
}
