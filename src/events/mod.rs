//! Events and Server-Initiated Notifications subsystem for vibe-daemon.
//! Defines system events, the asynchronous Event Bus, and transport dispatchers.

pub mod bus;

pub use bus::{DEFAULT_EVENT_CAPACITY, EventBus, EventBusStats, EventReceiver, ServerEvent};
