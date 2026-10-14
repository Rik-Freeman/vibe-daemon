//! Asynchronous event bus and server-initiated notification broker.
//! Provides bounded pub/sub messaging, deduplication, cooldown throttling,
//! and dropped event tracking across Stdio and SSE transport sinks.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, broadcast};

use crate::mcp::protocol::JsonRpcNotification;
use crate::tasks::TaskStatus;

/// Default maximum bounded capacity of the event bus ring buffer.
pub const DEFAULT_EVENT_CAPACITY: usize = 1024;

/// System events emitted by vibe-daemon subsystems.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ServerEvent {
    TaskCompleted { task_id: String, status: TaskStatus },
    ResourceUpdated { uri: String },
    MemoryThresholdExceeded { percent: f64 },
    ServiceDown { service: String },
    CertificateExpiring { domain: String, days: i64 },
}

impl ServerEvent {
    /// Deterministic deduplication key for throttling repeated events.
    pub fn deduplication_key(&self) -> String {
        match self {
            Self::TaskCompleted { task_id, .. } => format!("task:{task_id}"),
            Self::ResourceUpdated { uri } => format!("res:{uri}"),
            Self::MemoryThresholdExceeded { .. } => "mem:threshold".to_string(),
            Self::ServiceDown { service } => format!("svc:{service}"),
            Self::CertificateExpiring { domain, .. } => format!("cert:{domain}"),
        }
    }

    /// Default cooldown period before a duplicate event with the same key may be emitted again.
    pub fn default_cooldown(&self) -> Duration {
        match self {
            // Task completions are critical terminal events and must never be dropped by cooldown
            Self::TaskCompleted { .. } => Duration::ZERO,
            Self::ResourceUpdated { .. } => Duration::from_millis(150),
            Self::MemoryThresholdExceeded { .. } => Duration::from_secs(5),
            Self::ServiceDown { .. } => Duration::from_secs(5),
            Self::CertificateExpiring { .. } => Duration::from_secs(30),
        }
    }

    /// Converts a internal ServerEvent into a standard JSON-RPC 2.0 notification (without an id).
    pub fn to_jsonrpc_notification(&self) -> JsonRpcNotification {
        match self {
            Self::TaskCompleted { task_id, status } => JsonRpcNotification::new(
                "notifications/tasks/completed",
                Some(serde_json::json!({
                    "taskId": task_id,
                    "status": status,
                })),
            ),
            Self::ResourceUpdated { uri } => JsonRpcNotification::new(
                "notifications/resources/updated",
                Some(serde_json::json!({
                    "uri": uri,
                })),
            ),
            Self::MemoryThresholdExceeded { percent } => JsonRpcNotification::new(
                "notifications/system/memory_threshold",
                Some(serde_json::json!({
                    "percent": percent,
                })),
            ),
            Self::ServiceDown { service } => JsonRpcNotification::new(
                "notifications/services/down",
                Some(serde_json::json!({
                    "service": service,
                })),
            ),
            Self::CertificateExpiring { domain, days } => JsonRpcNotification::new(
                "notifications/certificates/expiring",
                Some(serde_json::json!({
                    "domain": domain,
                    "days": days,
                })),
            ),
        }
    }
}

/// Statistics snapshot of the event bus throughput and drop metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventBusStats {
    pub published: u64,
    pub throttled: u64,
    pub dropped: u64,
    pub active_subscribers: usize,
}

/// Receiver stream wrapper that automatically tallies dropped / lagged messages.
pub struct EventReceiver {
    inner: broadcast::Receiver<ServerEvent>,
    dropped_count: Arc<AtomicU64>,
}

impl EventReceiver {
    /// Awaits the next broadcast event, automatically accounting for any missed messages due to lag.
    pub async fn recv(&mut self) -> Result<ServerEvent, broadcast::error::RecvError> {
        loop {
            match self.inner.recv().await {
                Ok(evt) => return Ok(evt),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    self.dropped_count.fetch_add(n, Ordering::Relaxed);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Non-blocking check for the next broadcast event.
    pub fn try_recv(&mut self) -> Result<ServerEvent, broadcast::error::TryRecvError> {
        match self.inner.try_recv() {
            Ok(evt) => Ok(evt),
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                self.dropped_count.fetch_add(n, Ordering::Relaxed);
                self.inner.try_recv()
            }
            Err(e) => Err(e),
        }
    }
}

/// Transport-neutral Event Bus managing system event publication, deduplication, and subscriber dispatch.
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<ServerEvent>,
    cooldowns: Arc<RwLock<HashMap<String, Instant>>>,
    published_count: Arc<AtomicU64>,
    throttled_count: Arc<AtomicU64>,
    dropped_count: Arc<AtomicU64>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(DEFAULT_EVENT_CAPACITY)
    }
}

impl EventBus {
    /// Creates a new EventBus with the specified channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(16));
        Self {
            sender,
            cooldowns: Arc::new(RwLock::new(HashMap::new())),
            published_count: Arc::new(AtomicU64::new(0)),
            throttled_count: Arc::new(AtomicU64::new(0)),
            dropped_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Publishes an event applying its default deduplication cooldown.
    /// Returns `true` if published, or `false` if throttled as a duplicate.
    pub async fn publish(&self, event: ServerEvent) -> bool {
        let cooldown = event.default_cooldown();
        self.publish_with_cooldown(event, cooldown).await
    }

    /// Publishes an event with an explicit cooldown window.
    pub async fn publish_with_cooldown(&self, event: ServerEvent, cooldown: Duration) -> bool {
        if !cooldown.is_zero() {
            let key = event.deduplication_key();
            let now = Instant::now();
            let mut lock = self.cooldowns.write().await;
            if let Some(last) = lock.get(&key)
                && now.duration_since(*last) < cooldown
            {
                self.throttled_count.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            lock.insert(key, now);
        }

        self.published_count.fetch_add(1, Ordering::Relaxed);
        let _ = self.sender.send(event);
        true
    }

    /// Publishes an event immediately without deduplication or cooldown checks.
    pub fn publish_immediate(&self, event: ServerEvent) {
        self.published_count.fetch_add(1, Ordering::Relaxed);
        let _ = self.sender.send(event);
    }

    /// Creates a new subscription receiver to listen for server-initiated events.
    pub fn subscribe(&self) -> EventReceiver {
        EventReceiver {
            inner: self.sender.subscribe(),
            dropped_count: self.dropped_count.clone(),
        }
    }

    /// Records an event dropped externally (e.g. by a slow or full transport client buffer).
    pub fn record_dropped(&self) {
        self.dropped_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns current runtime metrics of the event broker.
    pub fn stats(&self) -> EventBusStats {
        EventBusStats {
            published: self.published_count.load(Ordering::Relaxed),
            throttled: self.throttled_count.load(Ordering::Relaxed),
            dropped: self.dropped_count.load(Ordering::Relaxed),
            active_subscribers: self.sender.receiver_count(),
        }
    }

    /// Resets runtime counters (primarily useful in tests).
    pub fn reset_stats(&self) {
        self.published_count.store(0, Ordering::Relaxed);
        self.throttled_count.store(0, Ordering::Relaxed);
        self.dropped_count.store(0, Ordering::Relaxed);
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jsonrpc_notification_format_no_id() {
        let event = ServerEvent::TaskCompleted {
            task_id: "task-123".to_string(),
            status: TaskStatus::Success,
        };

        let notif = event.to_jsonrpc_notification();
        assert_eq!(notif.jsonrpc, "2.0");
        assert_eq!(notif.method, "notifications/tasks/completed");

        let serialized = serde_json::to_string(&notif).unwrap();
        let val: serde_json::Value = serde_json::from_str(&serialized).unwrap();

        // Crucial requirement: notification must NOT contain an id field
        assert!(val.get("id").is_none());
        assert_eq!(val["jsonrpc"], "2.0");
        assert_eq!(val["method"], "notifications/tasks/completed");
        assert_eq!(val["params"]["taskId"], "task-123");
        assert_eq!(val["params"]["status"], "Success");
    }

    #[tokio::test]
    async fn test_event_bus_deduplication_and_throttling() {
        let bus = EventBus::new(32);
        let mut rx = bus.subscribe();

        let event = ServerEvent::MemoryThresholdExceeded { percent: 92.5 };

        // First emission succeeds
        let sent1 = bus
            .publish_with_cooldown(event.clone(), Duration::from_millis(500))
            .await;
        assert!(sent1);

        // Immediate duplicate emission within cooldown window is throttled
        let sent2 = bus
            .publish_with_cooldown(event.clone(), Duration::from_millis(500))
            .await;
        assert!(!sent2);

        let stats = bus.stats();
        assert_eq!(stats.published, 1);
        assert_eq!(stats.throttled, 1);

        let received = rx.recv().await.unwrap();
        assert_eq!(received, event);

        // After cooldown expires, publication succeeds again
        tokio::time::sleep(Duration::from_millis(550)).await;
        let sent3 = bus
            .publish_with_cooldown(event.clone(), Duration::from_millis(500))
            .await;
        assert!(sent3);
        assert_eq!(bus.stats().published, 2);
    }

    #[tokio::test]
    async fn test_event_bus_broadcast_and_lag_drop_tracking() {
        // Create small buffer of 16 items
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();

        // Publish 50 events without consuming
        for i in 0..50 {
            bus.publish_immediate(ServerEvent::ResourceUpdated {
                uri: format!("config://nginx/conf_{i}"),
            });
        }

        // Reading will lag and recover, updating dropped count
        let received = rx.recv().await.unwrap();
        let stats = bus.stats();

        assert_eq!(stats.published, 50);
        assert!(stats.dropped > 0, "Dropped events should be counted on lag");
        match received {
            ServerEvent::ResourceUpdated { uri } => assert!(uri.starts_with("config://nginx/")),
            _ => panic!("Unexpected event received"),
        }
    }
}
