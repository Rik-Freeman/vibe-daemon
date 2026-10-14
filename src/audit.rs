//! Structured audit logging for MCP tool calls with cryptographic tamper-evident
//! hash chaining, secret redaction, and guaranteed durability.
//! Produces JSON Lines (JSONL) records detailing tool invocation, arguments,
//! execution duration, status, and client information.

use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};

/// Default capacity for the bounded audit log message channel.
pub const DEFAULT_AUDIT_CHANNEL_CAPACITY: usize = 10_000;

/// Genesis hash for the initial record in the audit trail chain (64 hex zeros).
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// -----------------------------------------------------------------------------
// Secret Redaction Engine
// -----------------------------------------------------------------------------

static RE_PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*$")
        .expect("Valid private key regex")
});

static RE_BEARER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(bearer)\s+[A-Za-z0-9_\-\.\+/=]+").expect("Valid bearer token regex")
});

static RE_PARAM_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(^|[\s"';&?])(--password|--passwd|-password|-passwd|--token|-token|--secret|-secret|--api-key|--apikey|--access-token|password|passwd|secret|token|api_key|apikey)=([^\s"';&]+)"#)
        .expect("Valid param secret regex")
});

static RE_FLAG_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(^|[\s"';&])(--password|--passwd|-password|-passwd|--token|-token|--secret|-secret|--api-key|--apikey|--access-token)\s+([^\s"';&]+)"#)
        .expect("Valid flag secret regex")
});

/// Determines if a JSON object key indicates sensitive/credential information.
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("authorization")
        || lower.contains("private_key")
        || lower.contains("privkey")
        || lower.contains("credential")
}

/// Redacts sensitive patterns (Bearer tokens, private keys, passwords) from a raw string.
pub fn redact_string(s: &str) -> String {
    let s1 = RE_PRIVATE_KEY.replace_all(s, "[REDACTED PRIVATE KEY]");
    let s2 = RE_BEARER.replace_all(&s1, "$1 [REDACTED]");
    let s3 = RE_PARAM_SECRET.replace_all(&s2, "${1}${2}=[REDACTED]");
    let s4 = RE_FLAG_SECRET.replace_all(&s3, "${1}${2} [REDACTED]");
    s4.into_owned()
}

/// Recursively traverses a JSON Value, redacting sensitive keys and matching string patterns.
pub fn redact_value(val: &serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let mut redacted_map = serde_json::Map::new();
            for (k, v) in map {
                if is_sensitive_key(k) {
                    redacted_map.insert(
                        k.clone(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                } else {
                    redacted_map.insert(k.clone(), redact_value(v));
                }
            }
            serde_json::Value::Object(redacted_map)
        }
        serde_json::Value::Array(arr) => {
            let redacted_arr = arr.iter().map(redact_value).collect();
            serde_json::Value::Array(redacted_arr)
        }
        serde_json::Value::String(s) => serde_json::Value::String(redact_string(s)),
        other => other.clone(),
    }
}

/// Produces a deterministic canonical string for a JSON Value by recursively sorting object keys.
pub fn canonical_json_string(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            let entries: Vec<String> = sorted
                .into_iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json_string(v)
                    )
                })
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json_string).collect();
            format!("[{}]", items.join(","))
        }
        _ => serde_json::to_string(val).unwrap_or_default(),
    }
}

// -----------------------------------------------------------------------------
// Data Structures & Cryptographic Hashing
// -----------------------------------------------------------------------------

/// Structured audit trail record representing a single MCP tool execution
/// with cryptographic tamper-evident hash chaining.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    /// Monotonically increasing sequence number (1, 2, 3...).
    pub sequence: u64,
    /// ISO 8601 UTC timestamp of invocation (e.g., "2026-10-13T23:00:00Z").
    pub timestamp: String,
    /// Name of the invoked MCP tool.
    pub tool: String,
    /// Arguments passed to the tool as a JSON Value (with sensitive fields redacted).
    pub arguments: serde_json::Value,
    /// Outcome status ("success" or "error").
    pub status: String,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
    /// Connected MCP client name/info if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// Optional error details/message when status is "error".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Cryptographic hash of the immediately preceding record, or GENESIS_HASH for record #1.
    pub previous_hash: String,
    /// Cryptographic SHA-256 hash of this record and previous_hash.
    pub record_hash: String,
}

impl AuditRecord {
    /// Create a new AuditRecord. Sequence and hashes will be populated by AuditLogger upon queueing.
    pub fn new(
        tool: impl Into<String>,
        arguments: serde_json::Value,
        status: impl Into<String>,
        duration_ms: u64,
        client: Option<String>,
    ) -> Self {
        let redacted_arguments = redact_value(&arguments);
        Self {
            sequence: 0,
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            tool: tool.into(),
            arguments: redacted_arguments,
            status: status.into(),
            duration_ms,
            client,
            error: None,
            previous_hash: String::new(),
            record_hash: String::new(),
        }
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Sets sequence and previous_hash, and calculates the cryptographic record_hash.
    pub fn with_chain(mut self, sequence: u64, previous_hash: impl Into<String>) -> Self {
        self.sequence = sequence;
        self.previous_hash = previous_hash.into();
        self.record_hash = self.compute_hash();
        self
    }

    /// Computes the cryptographic SHA-256 hash of this record and its `previous_hash`.
    pub fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.sequence.to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(self.timestamp.as_bytes());
        hasher.update(b"|");
        hasher.update(self.tool.as_bytes());
        hasher.update(b"|");
        hasher.update(canonical_json_string(&self.arguments).as_bytes());
        hasher.update(b"|");
        hasher.update(self.status.as_bytes());
        hasher.update(b"|");
        hasher.update(self.duration_ms.to_string().as_bytes());
        hasher.update(b"|");
        if let Some(ref c) = self.client {
            hasher.update(c.as_bytes());
        }
        hasher.update(b"|");
        if let Some(ref e) = self.error {
            hasher.update(e.as_bytes());
        }
        hasher.update(b"|");
        hasher.update(self.previous_hash.as_bytes());

        let result = hasher.finalize();
        format!("{result:x}")
    }

    /// Verifies if the record's `record_hash` matches its computed hash.
    pub fn verify_hash(&self) -> bool {
        !self.record_hash.is_empty() && self.record_hash == self.compute_hash()
    }
}

// -----------------------------------------------------------------------------
// Audit Verification & Tamper Detection
// -----------------------------------------------------------------------------

/// Result of verifying the integrity of an audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerificationReport {
    pub total_records: usize,
    pub last_sequence: u64,
    pub last_hash: String,
}

/// Errors describing specific integrity failures in an audit log.
#[derive(Debug, PartialEq, Eq)]
pub enum AuditIntegrityError {
    Io {
        line: usize,
        message: String,
    },
    ParseError {
        line: usize,
        message: String,
    },
    SequenceMismatch {
        line: usize,
        expected: u64,
        found: u64,
    },
    PreviousHashMismatch {
        line: usize,
        sequence: u64,
        expected: String,
        found: String,
    },
    RecordHashMismatch {
        line: usize,
        sequence: u64,
        expected: String,
        found: String,
    },
}

impl std::fmt::Display for AuditIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { line, message } => write!(f, "I/O error at line {line}: {message}"),
            Self::ParseError { line, message } => {
                write!(f, "JSON parse error at line {line}: {message}")
            }
            Self::SequenceMismatch {
                line,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Sequence break at line {line}: expected sequence {expected}, found {found}"
                )
            }
            Self::PreviousHashMismatch {
                line,
                sequence,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Hash chain broken at line {line} (sequence {sequence}): expected previous_hash {expected}, found {found}"
                )
            }
            Self::RecordHashMismatch {
                line,
                sequence,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Tamper detected at line {line} (sequence {sequence}): record hash does not match content hash (expected {expected}, found {found})"
                )
            }
        }
    }
}

impl std::error::Error for AuditIntegrityError {}

/// Verifies the tamper-evident hash chain of raw JSONL audit log content.
pub fn verify_audit_log_content(
    content: &str,
) -> Result<AuditVerificationReport, AuditIntegrityError> {
    let mut expected_seq = 1u64;
    let mut expected_prev_hash = GENESIS_HASH.to_string();
    let mut total_records = 0;

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let record: AuditRecord =
            serde_json::from_str(trimmed).map_err(|e| AuditIntegrityError::ParseError {
                line: line_num,
                message: e.to_string(),
            })?;

        if record.sequence != expected_seq {
            return Err(AuditIntegrityError::SequenceMismatch {
                line: line_num,
                expected: expected_seq,
                found: record.sequence,
            });
        }

        if record.previous_hash != expected_prev_hash {
            return Err(AuditIntegrityError::PreviousHashMismatch {
                line: line_num,
                sequence: record.sequence,
                expected: expected_prev_hash,
                found: record.previous_hash,
            });
        }

        let computed = record.compute_hash();
        if record.record_hash != computed {
            return Err(AuditIntegrityError::RecordHashMismatch {
                line: line_num,
                sequence: record.sequence,
                expected: computed,
                found: record.record_hash,
            });
        }

        expected_prev_hash = record.record_hash.clone();
        expected_seq += 1;
        total_records += 1;
    }

    Ok(AuditVerificationReport {
        total_records,
        last_sequence: expected_seq - 1,
        last_hash: expected_prev_hash,
    })
}

/// Reads an audit log file and verifies its tamper-evident hash chain.
pub async fn verify_audit_log_file(
    path: &Path,
) -> Result<AuditVerificationReport, AuditIntegrityError> {
    if !path.exists() {
        return Ok(AuditVerificationReport {
            total_records: 0,
            last_sequence: 0,
            last_hash: GENESIS_HASH.to_string(),
        });
    }

    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| AuditIntegrityError::Io {
            line: 0,
            message: e.to_string(),
        })?;

    verify_audit_log_content(&content)
}

/// Synchronous version of `verify_audit_log_file` (used during startup before async runtime or in sync contexts).
pub fn verify_audit_log_file_sync(
    path: &Path,
) -> Result<AuditVerificationReport, AuditIntegrityError> {
    if !path.exists() {
        return Ok(AuditVerificationReport {
            total_records: 0,
            last_sequence: 0,
            last_hash: GENESIS_HASH.to_string(),
        });
    }

    let content = std::fs::read_to_string(path).map_err(|e| AuditIntegrityError::Io {
        line: 0,
        message: e.to_string(),
    })?;

    verify_audit_log_content(&content)
}

// -----------------------------------------------------------------------------
// AuditLogger Implementation
// -----------------------------------------------------------------------------

enum AuditMessage {
    Record(Box<AuditRecord>),
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Audit logger that writes tamper-evident, secret-redacted JSONL records
/// via a dedicated bounded background actor with guaranteed disk synchronization.
#[derive(Clone)]
pub struct AuditLogger {
    tx: Option<tokio::sync::mpsc::Sender<AuditMessage>>,
    log_path: Option<Arc<PathBuf>>,
    dropped_count: Arc<AtomicU64>,
}

impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogger")
            .field("log_path", &self.log_path)
            .field("enabled", &self.is_enabled())
            .field(
                "dropped_records",
                &self.dropped_count.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl AuditLogger {
    /// Create an AuditLogger with an optional target file path and default queue capacity.
    pub fn new(log_path: Option<PathBuf>) -> Self {
        Self::with_capacity(log_path, DEFAULT_AUDIT_CHANNEL_CAPACITY)
    }

    /// Create an AuditLogger with a custom bounded channel capacity.
    pub fn with_capacity(log_path: Option<PathBuf>, capacity: usize) -> Self {
        let Some(path) = log_path else {
            return Self {
                tx: None,
                log_path: None,
                dropped_count: Arc::new(AtomicU64::new(0)),
            };
        };

        // 1. Verify existing log file and determine starting sequence and previous_hash
        let (initial_seq, initial_hash) = match verify_audit_log_file_sync(&path) {
            Ok(report) => {
                if report.total_records > 0 {
                    info!(
                        path = %path.display(),
                        records = report.total_records,
                        last_seq = report.last_sequence,
                        "Audit log integrity verified on startup"
                    );
                }
                (report.last_sequence, report.last_hash)
            }
            Err(err) => {
                error!(
                    path = %path.display(),
                    error = %err,
                    "CRITICAL: Existing audit log failed integrity verification upon startup!"
                );
                (0, GENESIS_HASH.to_string())
            }
        };

        let path_arc = Arc::new(path);
        let path_clone = path_arc.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<AuditMessage>(capacity);
        let dropped_count = Arc::new(AtomicU64::new(0));

        tokio::spawn(async move {
            let mut current_seq = initial_seq;
            let mut current_hash = initial_hash;
            let mut file_opt: Option<tokio::fs::File> = None;

            while let Some(msg) = rx.recv().await {
                match msg {
                    AuditMessage::Record(mut record) => {
                        current_seq += 1;
                        record.sequence = current_seq;
                        record.previous_hash = current_hash.clone();
                        record.arguments = redact_value(&record.arguments);
                        record.record_hash = record.compute_hash();
                        current_hash = record.record_hash.clone();

                        let mut json = match serde_json::to_string(&record) {
                            Ok(j) => j,
                            Err(e) => {
                                error!(error = %e, "Failed to serialize audit record");
                                continue;
                            }
                        };
                        json.push('\n');

                        if file_opt.is_none() {
                            if let Some(parent) = path_clone.parent()
                                && !parent.as_os_str().is_empty()
                                && !parent.exists()
                            {
                                let _ = tokio::fs::create_dir_all(parent).await;
                            }
                            match tokio::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&*path_clone)
                                .await
                            {
                                Ok(f) => file_opt = Some(f),
                                Err(e) => {
                                    error!(path = %path_clone.display(), error = %e, "Failed to open audit log file");
                                    continue;
                                }
                            }
                        }

                        if let Some(ref mut file) = file_opt {
                            if let Err(e) = file.write_all(json.as_bytes()).await {
                                error!(path = %path_clone.display(), error = %e, "Failed to write audit record");
                            } else {
                                let _ = file.flush().await;
                            }
                        }
                    }
                    AuditMessage::Flush(ack) => {
                        if let Some(ref mut file) = file_opt {
                            let _ = file.flush().await;
                            let _ = file.sync_data().await;
                        }
                        let _ = ack.send(());
                    }
                }
            }

            // Draining completed; guarantee disk sync before actor terminates
            if let Some(ref mut file) = file_opt {
                let _ = file.flush().await;
                let _ = file.sync_data().await;
            }
        });

        Self {
            tx: Some(tx),
            log_path: Some(path_arc),
            dropped_count,
        }
    }

    /// Check if audit logging is enabled.
    pub fn is_enabled(&self) -> bool {
        self.tx.is_some()
    }

    /// Get target log path if configured.
    pub fn log_path(&self) -> Option<&Path> {
        self.log_path.as_deref().map(|p| p.as_path())
    }

    /// Number of dropped records due to channel overflow under sustained backpressure.
    pub fn dropped_records(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    /// Asynchronously queue an audit record to be written in the background.
    /// Redacts sensitive values and handles bounded channel backpressure.
    pub fn log_async(&self, mut record: AuditRecord) {
        if let Some(ref tx) = self.tx {
            record.arguments = redact_value(&record.arguments);
            let msg = AuditMessage::Record(Box::new(record));

            if let Err(tokio::sync::mpsc::error::TrySendError::Full(overflow_msg)) =
                tx.try_send(msg)
            {
                let tx_clone = tx.clone();
                let counter = self.dropped_count.clone();
                tokio::spawn(async move {
                    if tx_clone
                        .send_timeout(overflow_msg, std::time::Duration::from_millis(500))
                        .await
                        .is_err()
                    {
                        counter.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "Audit log queue sustained overflow; dropped audit record to protect memory bounds"
                        );
                    }
                });
            }
        }
    }

    /// Asynchronously queue an audit record with awaitable backpressure.
    pub async fn log_record(&self, mut record: AuditRecord) {
        if let Some(ref tx) = self.tx {
            record.arguments = redact_value(&record.arguments);
            let _ = tx.send(AuditMessage::Record(Box::new(record))).await;
        }
    }

    /// Wait for all previously queued audit records to be written and flushed to physical disk (`sync_data`).
    pub async fn flush(&self) {
        if let Some(ref tx) = self.tx {
            let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
            if tx.send(AuditMessage::Flush(ack_tx)).await.is_ok() {
                let _ = ack_rx.await;
            }
        }
    }

    /// Direct async logging with immediate disk sync.
    pub async fn log(&self, record: &AuditRecord) -> Result<(), std::io::Error> {
        if let Some(path) = &self.log_path {
            let mut rec = record.clone();
            rec.arguments = redact_value(&rec.arguments);
            if rec.record_hash.is_empty() {
                if rec.previous_hash.is_empty() {
                    rec.previous_hash = GENESIS_HASH.to_string();
                }
                if rec.sequence == 0 {
                    rec.sequence = 1;
                }
                rec.record_hash = rec.compute_hash();
            }
            append_audit_record(path, &rec).await?;
        }
        Ok(())
    }
}

async fn append_audit_record(path: &Path, record: &AuditRecord) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut json = serde_json::to_string(record)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    json.push('\n');

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;

    file.write_all(json.as_bytes()).await?;
    file.flush().await?;
    file.sync_data().await?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_audit_record_serialization() {
        let record = AuditRecord {
            sequence: 42,
            timestamp: "2026-10-13T23:00:00Z".to_string(),
            tool: "execute_safe_command".to_string(),
            arguments: json!({"command": "cargo test"}),
            status: "success".to_string(),
            duration_ms: 450,
            client: Some("claude-desktop".to_string()),
            error: None,
            previous_hash: GENESIS_HASH.to_string(),
            record_hash: "abcd1234ef5678".to_string(),
        };

        let json_str = serde_json::to_string(&record).unwrap();
        assert!(json_str.contains("\"sequence\":42"));
        assert!(json_str.contains("\"timestamp\":\"2026-10-13T23:00:00Z\""));
        assert!(json_str.contains("\"tool\":\"execute_safe_command\""));
        assert!(json_str.contains("\"command\":\"cargo test\""));
        assert!(json_str.contains("\"status\":\"success\""));
        assert!(json_str.contains("\"duration_ms\":450"));
        assert!(json_str.contains("\"client\":\"claude-desktop\""));
        assert!(json_str.contains("\"previous_hash\""));
        assert!(json_str.contains("\"record_hash\""));
        assert!(!json_str.contains("\"error\""));

        let deserialized: AuditRecord = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized, record);
    }

    #[tokio::test]
    async fn test_audit_record_with_error() {
        let record = AuditRecord::new(
            "execute_safe_command",
            json!({"command": "reboot"}),
            "error",
            12,
            Some("cursor".to_string()),
        )
        .with_error(
            "Rate limit exceeded: too many tool calls. Please wait a moment before retrying.",
        );

        let json_str = serde_json::to_string(&record).unwrap();
        assert!(json_str.contains("\"status\":\"error\""));
        assert!(json_str.contains("\"error\":\"Rate limit exceeded: too many tool calls. Please wait a moment before retrying.\""));
    }

    #[tokio::test]
    async fn test_audit_logger_write_and_read_jsonl() {
        let temp_dir = std::env::temp_dir().join(format!("vibe_audit_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let log_file = temp_dir.join("audit.jsonl");
        let logger = AuditLogger::new(Some(log_file.clone()));
        assert!(logger.is_enabled());

        let record1 = AuditRecord::new(
            "execute_safe_command",
            json!({"command": "cargo test"}),
            "success",
            320,
            Some("cursor".to_string()),
        );

        let record2 = AuditRecord::new(
            "manage_port",
            json!({"action": "close", "port": 22}),
            "error",
            5,
            Some("claude-desktop".to_string()),
        );

        // Test asynchronous queue and flush
        logger.log_async(record1);
        logger.log_async(record2);
        logger.flush().await;

        // Read and verify JSONL lines
        let content = tokio::fs::read_to_string(&log_file).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let parsed1: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed1.sequence, 1);
        assert_eq!(parsed1.tool, "execute_safe_command");
        assert_eq!(parsed1.status, "success");
        assert_eq!(parsed1.duration_ms, 320);
        assert_eq!(parsed1.client.as_deref(), Some("cursor"));
        assert_eq!(parsed1.previous_hash, GENESIS_HASH);
        assert!(parsed1.verify_hash());

        let parsed2: AuditRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed2.sequence, 2);
        assert_eq!(parsed2.tool, "manage_port");
        assert_eq!(parsed2.status, "error");
        assert_eq!(parsed2.duration_ms, 5);
        assert_eq!(parsed2.client.as_deref(), Some("claude-desktop"));
        assert_eq!(parsed2.previous_hash, parsed1.record_hash);
        assert!(parsed2.verify_hash());

        let report = verify_audit_log_file(&log_file).await.unwrap();
        assert_eq!(report.total_records, 2);
        assert_eq!(report.last_sequence, 2);
        assert_eq!(report.last_hash, parsed2.record_hash);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_audit_secret_redaction() {
        // 1. Redaction of Bearer tokens
        let s_bearer = "curl -H 'Authorization: Bearer my-secret-api-token-987' https://api.com";
        let r_bearer = redact_string(s_bearer);
        assert_eq!(
            r_bearer,
            "curl -H 'Authorization: Bearer [REDACTED]' https://api.com"
        );

        // 2. Redaction of command arguments
        let s_cmd = "mysql -u root --password=adminpass123 --token=secret_tok --api-key=key_456 db";
        let r_cmd = redact_string(s_cmd);
        assert_eq!(
            r_cmd,
            "mysql -u root --password=[REDACTED] --token=[REDACTED] --api-key=[REDACTED] db"
        );

        // 3. Redaction of space-separated flags
        let s_flag = "login --password mysecretpass --token abc";
        let r_flag = redact_string(s_flag);
        assert_eq!(r_flag, "login --password [REDACTED] --token [REDACTED]");

        // 4. Redaction of Private Keys
        let s_key = "prefix -----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA...\n-----END RSA PRIVATE KEY----- suffix";
        let r_key = redact_string(s_key);
        assert_eq!(r_key, "prefix [REDACTED PRIVATE KEY] suffix");

        let s_openssh =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza...\n-----END OPENSSH PRIVATE KEY-----";
        let r_openssh = redact_string(s_openssh);
        assert_eq!(r_openssh, "[REDACTED PRIVATE KEY]");

        // 5. Redaction of JSON structure
        let val = json!({
            "command": "curl -H 'Authorization: Bearer tok123'",
            "password": "plain_password",
            "auth_token": "secret_session",
            "nested": {
                "private_key": "-----BEGIN EC PRIVATE KEY-----\nxyz\n-----END EC PRIVATE KEY-----",
                "normal": "safe_value"
            }
        });
        let redacted = redact_value(&val);
        assert_eq!(
            redacted["command"],
            "curl -H 'Authorization: Bearer [REDACTED]'"
        );
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["auth_token"], "[REDACTED]");
        assert_eq!(redacted["nested"]["private_key"], "[REDACTED]");
        assert_eq!(redacted["nested"]["normal"], "safe_value");
    }

    #[tokio::test]
    async fn test_audit_hash_chain_tamper_detection() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_tamper_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let log_file = temp_dir.join("tamper_audit.jsonl");

        let logger = AuditLogger::new(Some(log_file.clone()));
        for i in 1..=3 {
            logger.log_async(AuditRecord::new(
                format!("tool_{i}"),
                json!({"arg": i}),
                "success",
                10 * i,
                None,
            ));
        }
        logger.flush().await;

        // Verify clean chain
        let report = verify_audit_log_file(&log_file).await.unwrap();
        assert_eq!(report.total_records, 3);
        assert_eq!(report.last_sequence, 3);

        // Tamper test 1: Modify content in record 2
        let content = tokio::fs::read_to_string(&log_file).await.unwrap();
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

        let mut tampered_rec: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        tampered_rec["arguments"]["arg"] = json!(999);
        lines[1] = serde_json::to_string(&tampered_rec).unwrap();
        let tampered_content = lines.join("\n");

        let err = verify_audit_log_content(&tampered_content).unwrap_err();
        match err {
            AuditIntegrityError::RecordHashMismatch { line, sequence, .. } => {
                assert_eq!(line, 2);
                assert_eq!(sequence, 2);
            }
            other => panic!("Expected RecordHashMismatch, got {other:?}"),
        }

        // Tamper test 2: Sequence break (remove record 2)
        let mut lines2: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        lines2.remove(1);
        let tampered_content2 = lines2.join("\n");

        let err2 = verify_audit_log_content(&tampered_content2).unwrap_err();
        match err2 {
            AuditIntegrityError::SequenceMismatch {
                line,
                expected,
                found,
            } => {
                assert_eq!(line, 2);
                assert_eq!(expected, 2);
                assert_eq!(found, 3);
            }
            other => panic!("Expected SequenceMismatch, got {other:?}"),
        }

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_audit_continuation_across_restart() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_restart_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let log_file = temp_dir.join("restart_audit.jsonl");

        // 1. First run: write records 1 and 2
        {
            let logger1 = AuditLogger::new(Some(log_file.clone()));
            logger1.log_async(AuditRecord::new("tool_1", json!({}), "success", 10, None));
            logger1.log_async(AuditRecord::new("tool_2", json!({}), "success", 20, None));
            logger1.flush().await;
        }

        // 2. Restart: start new logger on same file
        {
            let logger2 = AuditLogger::new(Some(log_file.clone()));
            logger2.log_async(AuditRecord::new("tool_3", json!({}), "success", 30, None));
            logger2.log_async(AuditRecord::new("tool_4", json!({}), "success", 40, None));
            logger2.flush().await;
        }

        // 3. Verify entire 4-record chain is unbroken
        let report = verify_audit_log_file(&log_file).await.unwrap();
        assert_eq!(report.total_records, 4);
        assert_eq!(report.last_sequence, 4);

        let content = tokio::fs::read_to_string(&log_file).await.unwrap();
        let records: Vec<AuditRecord> = content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].sequence, 1);
        assert_eq!(records[1].sequence, 2);
        assert_eq!(records[2].sequence, 3);
        assert_eq!(records[3].sequence, 4);
        assert_eq!(records[2].previous_hash, records[1].record_hash);
        assert_eq!(records[3].previous_hash, records[2].record_hash);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_audit_logger_disabled() {
        let logger = AuditLogger::new(None);
        assert!(!logger.is_enabled());
        assert!(logger.log_path().is_none());

        let record = AuditRecord::new("get_system_status", json!({}), "success", 10, None);

        logger.log_async(record.clone());
        logger.flush().await;

        assert!(logger.log(&record).await.is_ok());
    }

    #[tokio::test]
    async fn test_audit_durability_and_flush() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_durability_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let log_file = temp_dir.join("durability_audit.jsonl");

        let logger = AuditLogger::new(Some(log_file.clone()));

        // Queue 10 records rapidly
        for i in 1..=10 {
            logger.log_async(AuditRecord::new(
                format!("batch_tool_{i}"),
                json!({"index": i, "secret_key": "mysecret"}),
                "success",
                i * 5,
                Some("test-client".to_string()),
            ));
        }

        // Flush ensures all 10 records are written and synced to disk
        logger.flush().await;

        let report = verify_audit_log_file(&log_file).await.unwrap();
        assert_eq!(report.total_records, 10);
        assert_eq!(report.last_sequence, 10);

        // Verify secret redaction happened for all records
        let content = tokio::fs::read_to_string(&log_file).await.unwrap();
        assert!(!content.contains("mysecret"));
        assert!(content.contains("[REDACTED]"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_audit_bounded_channel_capacity() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_bounded_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let log_file = temp_dir.join("bounded_audit.jsonl");

        // Small capacity channel
        let logger = AuditLogger::with_capacity(Some(log_file.clone()), 4);
        for i in 1..=5 {
            logger.log_async(AuditRecord::new(
                format!("tool_{i}"),
                json!({"id": i}),
                "success",
                10,
                None,
            ));
        }

        logger.flush().await;

        let report = verify_audit_log_file(&log_file).await.unwrap();
        assert!(report.total_records >= 4);
        assert_eq!(report.last_sequence as usize, report.total_records);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
