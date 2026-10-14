//! Transport subsystem for vibe-daemon.
//! Supports local standard I/O (stdio) and remote network (HTTP / Server-Sent Events) transports.

pub mod http;
pub mod stdio;

pub use http::*;
pub use stdio::*;

use std::fmt;
use std::str::FromStr;

/// Available MCP transport protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportType {
    /// Local standard input/output transport (default for MCP servers).
    #[default]
    Stdio,
    /// Streamable HTTP POST transport.
    Http,
    /// Server-Sent Events (SSE) remote transport.
    Sse,
}

impl FromStr for TransportType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().trim() {
            "stdio" => Ok(TransportType::Stdio),
            "http" => Ok(TransportType::Http),
            "sse" => Ok(TransportType::Sse),
            other => Err(format!(
                "Invalid transport '{other}'. Supported values: stdio, http, sse"
            )),
        }
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::Stdio => write!(f, "stdio"),
            TransportType::Http => write!(f, "http"),
            TransportType::Sse => write!(f, "sse"),
        }
    }
}
