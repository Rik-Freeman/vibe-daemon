//! Rate limiting and abuse prevention module for vibe-daemon.
//! Protects the server from runaway AI loops, spam, or high-frequency abuse
//! by implementing a thread-safe Sliding Window counter.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Errors returned when rate limits are exceeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitError {
    /// Global limit across all tools exceeded.
    GlobalLimitExceeded { limit: u32, retry_after_secs: u64 },
    /// Per-tool limit exceeded for a specific tool.
    ToolLimitExceeded {
        tool: String,
        limit: u32,
        retry_after_secs: u64,
    },
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GlobalLimitExceeded { .. } => {
                write!(
                    f,
                    "Rate limit exceeded: too many tool calls. Please wait a moment before retrying."
                )
            }
            Self::ToolLimitExceeded { tool, limit, .. } => {
                write!(
                    f,
                    "Rate limit exceeded: too many calls to tool '{tool}' (limit: {limit}/min). Please wait a moment before retrying."
                )
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

#[derive(Debug)]
struct RateLimiterInner {
    max_calls_per_minute: u32,
    tool_limits: HashMap<String, u32>,
    window_duration: Duration,
    global_calls: VecDeque<Instant>,
    tool_calls: HashMap<String, VecDeque<Instant>>,
}

/// Thread-safe Sliding Window rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<RateLimiterInner>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(60, HashMap::new())
    }
}

impl RateLimiter {
    /// Create a new RateLimiter with default 60-second sliding window.
    pub fn new(max_calls_per_minute: u32, tool_limits: HashMap<String, u32>) -> Self {
        Self::with_window(max_calls_per_minute, tool_limits, Duration::from_secs(60))
    }

    /// Create a RateLimiter with custom window duration (useful for tests or alternate intervals).
    pub fn with_window(
        max_calls_per_minute: u32,
        tool_limits: HashMap<String, u32>,
        window_duration: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RateLimiterInner {
                max_calls_per_minute,
                tool_limits,
                window_duration,
                global_calls: VecDeque::new(),
                tool_calls: HashMap::new(),
            })),
        }
    }

    /// Create a RateLimiter from security configuration settings.
    pub fn from_config(config: &crate::config::SecurityConfig) -> Self {
        Self::new(config.max_calls_per_minute, config.tool_limits.clone())
    }

    /// Check if a tool invocation is allowed and record it.
    /// Returns `Ok(())` if permitted, or `Err(RateLimitError)` if rejected.
    pub fn check_and_record(&self, tool: &str) -> Result<(), RateLimitError> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let window = inner.window_duration;

        // 1. Evict expired entries from global queue
        while let Some(&first) = inner.global_calls.front() {
            if now.saturating_duration_since(first) >= window {
                inner.global_calls.pop_front();
            } else {
                break;
            }
        }

        // 2. Check global limit (0 means disabled)
        if inner.max_calls_per_minute > 0
            && inner.global_calls.len() as u32 >= inner.max_calls_per_minute
        {
            let oldest = inner.global_calls.front().copied().unwrap_or(now);
            let elapsed = now.saturating_duration_since(oldest);
            let retry_after_secs = window.saturating_sub(elapsed).as_secs().max(1);
            return Err(RateLimitError::GlobalLimitExceeded {
                limit: inner.max_calls_per_minute,
                retry_after_secs,
            });
        }

        // 3. Check tool-specific limit if configured
        if let Some(&limit) = inner.tool_limits.get(tool)
            && limit > 0
        {
            let queue = inner.tool_calls.entry(tool.to_string()).or_default();
            while let Some(&first) = queue.front() {
                if now.saturating_duration_since(first) >= window {
                    queue.pop_front();
                } else {
                    break;
                }
            }

            if queue.len() as u32 >= limit {
                let oldest = queue.front().copied().unwrap_or(now);
                let elapsed = now.saturating_duration_since(oldest);
                let retry_after_secs = window.saturating_sub(elapsed).as_secs().max(1);
                return Err(RateLimitError::ToolLimitExceeded {
                    tool: tool.to_string(),
                    limit,
                    retry_after_secs,
                });
            }
        }

        // 4. Record invocation
        inner.global_calls.push_back(now);
        if inner.tool_limits.contains_key(tool) {
            inner
                .tool_calls
                .entry(tool.to_string())
                .or_default()
                .push_back(now);
        }

        Ok(())
    }

    /// Reset all call history counters.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.global_calls.clear();
        inner.tool_calls.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(5, HashMap::new());
        for _ in 0..5 {
            assert!(limiter.check_and_record("get_system_status").is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_global_excess() {
        let limiter = RateLimiter::new(3, HashMap::new());
        assert!(limiter.check_and_record("tool_a").is_ok());
        assert!(limiter.check_and_record("tool_b").is_ok());
        assert!(limiter.check_and_record("tool_c").is_ok());

        // 4th call exceeds limit
        let res = limiter.check_and_record("tool_d");
        assert!(res.is_err());
        match res.unwrap_err() {
            RateLimitError::GlobalLimitExceeded { limit, .. } => {
                assert_eq!(limit, 3);
            }
            _ => panic!("Expected GlobalLimitExceeded"),
        }
    }

    #[test]
    fn test_rate_limiter_error_message_format() {
        let err = RateLimitError::GlobalLimitExceeded {
            limit: 60,
            retry_after_secs: 15,
        };
        assert_eq!(
            err.to_string(),
            "Rate limit exceeded: too many tool calls. Please wait a moment before retrying."
        );

        let tool_err = RateLimitError::ToolLimitExceeded {
            tool: "execute_safe_command".to_string(),
            limit: 10,
            retry_after_secs: 20,
        };
        assert_eq!(
            tool_err.to_string(),
            "Rate limit exceeded: too many calls to tool 'execute_safe_command' (limit: 10/min). Please wait a moment before retrying."
        );
    }

    #[test]
    fn test_rate_limiter_tool_specific_limit() {
        let mut tool_limits = HashMap::new();
        tool_limits.insert("execute_safe_command".to_string(), 2);

        let limiter = RateLimiter::new(10, tool_limits);

        // First 2 calls to execute_safe_command succeed
        assert!(limiter.check_and_record("execute_safe_command").is_ok());
        assert!(limiter.check_and_record("execute_safe_command").is_ok());

        // 3rd call to execute_safe_command is blocked
        let res = limiter.check_and_record("execute_safe_command");
        assert!(res.is_err());
        match res.unwrap_err() {
            RateLimitError::ToolLimitExceeded { tool, limit, .. } => {
                assert_eq!(tool, "execute_safe_command");
                assert_eq!(limit, 2);
            }
            _ => panic!("Expected ToolLimitExceeded"),
        }

        // Other tools still succeed because global limit (10) is not reached
        assert!(limiter.check_and_record("get_system_status").is_ok());
    }

    #[test]
    fn test_rate_limiter_sliding_window_recovery() {
        // Use a short 50ms window
        let limiter = RateLimiter::with_window(2, HashMap::new(), Duration::from_millis(50));
        assert!(limiter.check_and_record("test").is_ok());
        assert!(limiter.check_and_record("test").is_ok());
        assert!(limiter.check_and_record("test").is_err());

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(60));

        // After window expires, should be allowed again
        assert!(limiter.check_and_record("test").is_ok());
    }

    #[test]
    fn test_rate_limiter_disabled_when_zero() {
        let limiter = RateLimiter::new(0, HashMap::new());
        for _ in 0..100 {
            assert!(limiter.check_and_record("tool").is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_reset() {
        let limiter = RateLimiter::new(1, HashMap::new());
        assert!(limiter.check_and_record("test").is_ok());
        assert!(limiter.check_and_record("test").is_err());

        limiter.reset();
        assert!(limiter.check_and_record("test").is_ok());
    }
}
