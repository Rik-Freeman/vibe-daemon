//! Events and Server-Initiated Notifications subsystem for vibe-daemon.
//! Defines system events, the asynchronous Event Bus, and transport dispatchers.

pub mod bus;
pub mod producers;

pub use bus::{DEFAULT_EVENT_CAPACITY, EventBus, EventBusStats, EventReceiver, ServerEvent};
pub use producers::{
    SystemEventCheckOptions, check_certificates, check_memory_threshold, check_services,
    check_system_events, evaluate_memory_threshold, spawn_system_event_producer,
};
