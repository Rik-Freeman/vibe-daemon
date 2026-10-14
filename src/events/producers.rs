//! Active Background Producers for System Health and Threshold Events.
//! Periodically evaluates host memory consumption, critical daemon statuses,
//! and SSL/TLS certificate expiration to emit `ServerEvent` notifications onto the EventBus.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use crate::config::Config;
use crate::events::bus::{EventBus, ServerEvent};
use crate::inspector::{MemoryInfo, check_service_status, collect_memory_info};
use crate::tools::ssl::{
    DEFAULT_CERT_DIRS, EXPIRY_WARNING_DAYS_THRESHOLD, inspect_local_cert_file,
    query_remote_domain_cert,
};

/// Configuration options for system event evaluations.
#[derive(Debug, Clone)]
pub struct SystemEventCheckOptions {
    /// Memory usage percentage threshold above which `MemoryThresholdExceeded` is emitted (e.g. 90.0).
    pub memory_threshold_percent: f64,
    /// Number of days before certificate expiration to trigger `CertificateExpiring` (default: 30).
    pub cert_expiry_warning_days: i64,
    /// Certificate directories to scan for .crt/.pem files.
    pub cert_dirs: Vec<PathBuf>,
    /// Optional specific domain names or hostnames to query for TLS certificate expiry.
    pub domains_to_check: Vec<String>,
    /// Duplicate suppression window for memory alerts.
    pub memory_cooldown: Duration,
    /// Duplicate suppression window for service alerts.
    pub service_cooldown: Duration,
    /// Duplicate suppression window for certificate alerts.
    pub certificate_cooldown: Duration,
}

impl Default for SystemEventCheckOptions {
    fn default() -> Self {
        Self {
            memory_threshold_percent: 90.0,
            cert_expiry_warning_days: EXPIRY_WARNING_DAYS_THRESHOLD,
            cert_dirs: DEFAULT_CERT_DIRS.iter().map(PathBuf::from).collect(),
            domains_to_check: Vec::new(),
            memory_cooldown: Duration::from_secs(300),
            service_cooldown: Duration::from_secs(60),
            certificate_cooldown: Duration::from_secs(3600),
        }
    }
}

/// Evaluates memory info against the configured threshold.
pub fn evaluate_memory_threshold(
    memory_info: &MemoryInfo,
    threshold_percent: f64,
) -> Option<ServerEvent> {
    if memory_info.total_bytes > 0 {
        let percent = (memory_info.used_bytes as f64 / memory_info.total_bytes as f64) * 100.0;
        if percent >= threshold_percent {
            return Some(ServerEvent::MemoryThresholdExceeded { percent });
        }
    }
    None
}

/// Checks host memory usage and returns a `MemoryThresholdExceeded` event if over threshold.
pub async fn check_memory_threshold(opts: &SystemEventCheckOptions) -> Option<ServerEvent> {
    let mem = collect_memory_info().await;
    evaluate_memory_threshold(&mem, opts.memory_threshold_percent)
}

/// Checks configured key system services and emits `ServiceDown` for any inactive/failed services.
pub async fn check_services(config: &Config) -> Vec<ServerEvent> {
    let mut events = Vec::new();
    for svc in &config.inspector.key_services {
        let status = check_service_status(svc).await;
        let s = status.status.trim().to_lowercase();
        if s != "active" {
            events.push(ServerEvent::ServiceDown {
                service: svc.clone(),
            });
        }
    }
    events
}

/// Checks local certificate directories and optional remote domains for expiring SSL certificates.
pub async fn check_certificates(opts: &SystemEventCheckOptions) -> Vec<ServerEvent> {
    let mut events = Vec::new();
    let now = chrono::Utc::now();

    // 1. Scan local certificate directories
    for dir in &opts.cert_dirs {
        if !dir.exists() || !dir.is_dir() {
            continue;
        }

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let ext = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if (ext == "crt" || ext == "pem")
                        && let Ok(fields) = inspect_local_cert_file(&path).await
                    {
                        let days = (fields.not_after_dt - now).num_days();
                        if days <= opts.cert_expiry_warning_days {
                            let domain =
                                fields.domains.into_iter().next().unwrap_or(fields.subject);
                            events.push(ServerEvent::CertificateExpiring { domain, days });
                        }
                    }
                }
            }
        }
    }

    // 2. Query remote domains if configured
    for domain in &opts.domains_to_check {
        if let Ok((_subject, _issuer, _not_after_str, not_after_dt)) =
            query_remote_domain_cert(domain, 443).await
        {
            let days = (not_after_dt - now).num_days();
            if days <= opts.cert_expiry_warning_days {
                events.push(ServerEvent::CertificateExpiring {
                    domain: domain.clone(),
                    days,
                });
            }
        }
    }

    events
}

/// Evaluates memory, key services, and SSL certificates, publishing all triggered events to the EventBus.
pub async fn check_system_events(
    config: &Config,
    bus: &EventBus,
    opts: &SystemEventCheckOptions,
) -> Vec<ServerEvent> {
    let mut triggered = Vec::new();

    // 1. Memory usage check
    if let Some(mem_evt) = check_memory_threshold(opts).await {
        bus.publish_with_cooldown(mem_evt.clone(), opts.memory_cooldown)
            .await;
        triggered.push(mem_evt);
    }

    // 2. Service health check
    let svc_events = check_services(config).await;
    for evt in svc_events {
        bus.publish_with_cooldown(evt.clone(), opts.service_cooldown)
            .await;
        triggered.push(evt);
    }

    // 3. Certificate expiration check
    let cert_events = check_certificates(opts).await;
    for evt in cert_events {
        bus.publish_with_cooldown(evt.clone(), opts.certificate_cooldown)
            .await;
        triggered.push(evt);
    }

    triggered
}

/// Spawns a background task running periodic system health evaluation at the specified interval.
pub fn spawn_system_event_producer(
    config: Arc<Config>,
    bus: Arc<EventBus>,
    opts: SystemEventCheckOptions,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        debug!(
            interval_secs = interval.as_secs(),
            "Starting system event producer loop"
        );
        let mut timer = tokio::time::interval(interval);
        // Initial tick completes immediately
        timer.tick().await;

        loop {
            timer.tick().await;
            let triggered = check_system_events(&config, &bus, &opts).await;
            if !triggered.is_empty() {
                debug!(
                    count = triggered.len(),
                    "System event producer published health events"
                );
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_memory_threshold() {
        let mem_under = MemoryInfo {
            total_bytes: 1000,
            available_bytes: 300,
            used_bytes: 700,
        };
        assert_eq!(evaluate_memory_threshold(&mem_under, 80.0), None);

        let mem_over = MemoryInfo {
            total_bytes: 1000,
            available_bytes: 100,
            used_bytes: 900,
        };
        let evt = evaluate_memory_threshold(&mem_over, 80.0);
        assert!(matches!(
            evt,
            Some(ServerEvent::MemoryThresholdExceeded { percent }) if (percent - 90.0).abs() < f64::EPSILON
        ));
    }

    #[tokio::test]
    async fn test_check_system_events_with_bus() {
        let bus = EventBus::new(32);
        let mut rx = bus.subscribe();

        let mut config = Config::default();
        config.inspector.key_services = vec!["nonexistent-test-service-12345".to_string()];

        let opts = SystemEventCheckOptions {
            memory_threshold_percent: 0.0, // trigger immediately if memory exists
            cert_expiry_warning_days: 30,
            cert_dirs: Vec::new(),
            domains_to_check: Vec::new(),
            memory_cooldown: Duration::ZERO,
            service_cooldown: Duration::ZERO,
            certificate_cooldown: Duration::ZERO,
        };

        let events = check_system_events(&config, &bus, &opts).await;
        assert!(!events.is_empty());

        // Ensure events were published to the bus
        let received = rx.recv().await.expect("Failed to receive event from bus");
        assert!(events.contains(&received));
    }

    #[tokio::test]
    async fn test_spawned_system_event_producer_publishes_and_stops() {
        let bus = Arc::new(EventBus::new(32));
        let mut rx = bus.subscribe();
        let mut config = Config::default();
        config.inspector.key_services = vec!["nonexistent-producer-test-service".to_string()];
        let opts = SystemEventCheckOptions {
            memory_threshold_percent: 101.0,
            cert_expiry_warning_days: 30,
            cert_dirs: Vec::new(),
            domains_to_check: Vec::new(),
            memory_cooldown: Duration::ZERO,
            service_cooldown: Duration::ZERO,
            certificate_cooldown: Duration::ZERO,
        };

        let handle =
            spawn_system_event_producer(Arc::new(config), bus, opts, Duration::from_millis(10));
        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("producer did not publish in time")
            .expect("event bus closed unexpectedly");
        assert!(matches!(event, ServerEvent::ServiceDown { .. }));
        handle.abort();
        let _ = handle.await;
    }
}
