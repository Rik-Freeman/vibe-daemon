//! File operations module for vibe-daemon.
//! Provides safe filesystem inspection, file reading, file writing, search,
//! and log tailing with strict path traversal and system file protection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::warn;

/// Structured directory entry metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub name: String,
    pub path: String,
    pub entry_type: String, // "file", "directory", "symlink", "other"
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_utc: Option<String>,
}

/// Paginated directory listing result with deterministic continuation token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListDirectoryResult {
    pub entries: Vec<DirEntryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub truncated: bool,
}

/// Encodes a sort path into an opaque hexadecimal pagination cursor token.
pub fn encode_cursor(path: &str) -> String {
    let mut out = String::with_capacity(path.len() * 2);
    for b in path.as_bytes() {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// Decodes an opaque hexadecimal pagination cursor token into a sort path.
pub fn decode_cursor(cursor: &str) -> Result<String, String> {
    let trimmed = cursor.trim();
    if trimmed.is_empty() {
        return Err("Cursor token cannot be empty".to_string());
    }
    if !trimmed.len().is_multiple_of(2) {
        return Err("Invalid cursor token length".to_string());
    }
    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    for i in (0..trimmed.len()).step_by(2) {
        let byte = u8::from_str_radix(&trimmed[i..i + 2], 16)
            .map_err(|e| format!("Invalid cursor hex encoding: {e}"))?;
        bytes.push(byte);
    }
    String::from_utf8(bytes).map_err(|e| format!("Invalid cursor UTF-8 encoding: {e}"))
}

/// Structured search match result.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchMatch {
    pub path: String,
    pub match_type: String, // "filename" or "content"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

// -----------------------------------------------------------------------------
// 1. list_directory (Deterministic cursor-based pagination)
// -----------------------------------------------------------------------------

/// Safety limit for scanned directory nodes to prevent memory exhaustion on massive trees.
pub const MAX_COLLECT_ENTRIES: usize = 5000;

/// Lists directory contents up to `max_depth` (default 1, max 5) with cursor-based pagination.
/// Returns [`ListDirectoryResult`] containing `entries`, optional `next_cursor`, and `truncated`.
pub async fn list_directory(
    path_str: &str,
    max_depth: Option<usize>,
    limit: Option<usize>,
    cursor: Option<&str>,
) -> Result<ListDirectoryResult, String> {
    let trimmed = path_str.trim();
    if trimmed.is_empty() {
        return Err("Directory path cannot be empty".to_string());
    }

    let root_path = Path::new(trimmed);
    let normalized = crate::guard::fs_guard::normalize_path(root_path)
        .map_err(|e| format!("Invalid path: {e}"))?;

    let meta = tokio::fs::metadata(&normalized)
        .await
        .map_err(|e| format!("Cannot access directory '{}': {e}", normalized.display()))?;

    if !meta.is_dir() {
        return Err(format!(
            "Path '{}' is not a directory",
            normalized.display()
        ));
    }

    let depth_limit = max_depth.unwrap_or(1).clamp(1, 5);
    let page_limit = limit.unwrap_or(100).clamp(1, 500);

    let after_path = match cursor {
        Some(c) if !c.trim().is_empty() => Some(decode_cursor(c)?),
        _ => None,
    };

    let mut all_entries = Vec::new();
    collect_dir_entries(&normalized, 1, depth_limit, &mut all_entries).await?;

    // Sort entries deterministically by normalized path
    all_entries.sort_by(|a, b| a.path.cmp(&b.path));

    // Filter items strictly after cursor position
    let filtered_entries: Vec<DirEntryInfo> = if let Some(ref after) = after_path {
        all_entries
            .into_iter()
            .filter(|e| &e.path > after)
            .collect()
    } else {
        all_entries
    };

    let total_remaining = filtered_entries.len();
    if total_remaining > page_limit {
        let mut page_entries = filtered_entries;
        let remainder = page_entries.split_off(page_limit);
        let last_path = page_entries.last().map(|e| e.path.as_str()).unwrap_or("");
        let next_cursor = if !last_path.is_empty() && !remainder.is_empty() {
            Some(encode_cursor(last_path))
        } else {
            None
        };

        Ok(ListDirectoryResult {
            entries: page_entries,
            next_cursor,
            truncated: true,
        })
    } else {
        Ok(ListDirectoryResult {
            entries: filtered_entries,
            next_cursor: None,
            truncated: false,
        })
    }
}

async fn collect_dir_entries(
    dir: &Path,
    current_depth: usize,
    max_depth: usize,
    acc: &mut Vec<DirEntryInfo>,
) -> Result<(), String> {
    if acc.len() >= MAX_COLLECT_ENTRIES {
        return Err(format!(
            "Directory scan exceeds safety limit of {MAX_COLLECT_ENTRIES} entries; narrow the path or depth"
        ));
    }

    let mut read_dir = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "Cannot read directory");
            return Ok(());
        }
    };

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        if acc.len() >= MAX_COLLECT_ENTRIES {
            return Err(format!(
                "Directory scan exceeds safety limit of {MAX_COLLECT_ENTRIES} entries; narrow the path or depth"
            ));
        }

        let entry_path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();

        let (entry_type, size_bytes, modified_utc) = match entry.metadata().await {
            Ok(m) => {
                let et = if m.is_dir() {
                    "directory".to_string()
                } else if m.is_symlink() {
                    "symlink".to_string()
                } else if m.is_file() {
                    "file".to_string()
                } else {
                    "other".to_string()
                };

                let mod_time = m.modified().ok().map(|st| {
                    let dt: DateTime<Utc> = st.into();
                    dt.to_rfc3339()
                });

                (et, m.len(), mod_time)
            }
            Err(_) => ("unknown".to_string(), 0, None),
        };

        let is_dir = entry_type == "directory";
        let display_path = entry_path.to_string_lossy().replace('\\', "/");

        acc.push(DirEntryInfo {
            name: file_name,
            path: display_path,
            entry_type,
            size_bytes,
            modified_utc,
        });

        if is_dir && current_depth < max_depth {
            Box::pin(collect_dir_entries(
                &entry_path,
                current_depth + 1,
                max_depth,
                acc,
            ))
            .await?;
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// 2. read_file
// -----------------------------------------------------------------------------

/// Safely reads the text content of a file with size limits (default 1MB).
pub async fn read_file(path_str: &str, max_bytes: Option<usize>) -> Result<String, String> {
    let trimmed = path_str.trim();
    if trimmed.is_empty() {
        return Err("File path cannot be empty".to_string());
    }

    let path = Path::new(trimmed);

    // Security check: verify path is safe to read
    crate::guard::fs_guard::check_file_read_safety(path)
        .map_err(|e| format!("Security Violation: {e}"))?;

    let normalized =
        crate::guard::fs_guard::normalize_path(path).map_err(|e| format!("Invalid path: {e}"))?;

    let meta = tokio::fs::metadata(&normalized)
        .await
        .map_err(|e| format!("Cannot access file '{}': {e}", normalized.display()))?;

    if meta.is_dir() {
        return Err(format!(
            "Path '{}' is a directory, not a file",
            normalized.display()
        ));
    }

    let limit = max_bytes.unwrap_or(1024 * 1024).clamp(1, 10 * 1024 * 1024);
    if meta.len() > limit as u64 {
        return Err(format!(
            "File size ({} bytes) exceeds maximum allowed limit of {} bytes",
            meta.len(),
            limit
        ));
    }

    let bytes = tokio::fs::read(&normalized)
        .await
        .map_err(|e| format!("Failed to read file '{}': {e}", normalized.display()))?;

    Ok(String::from_utf8_lossy(&bytes).to_string())
}

// -----------------------------------------------------------------------------
// 3. write_file & atomic_write_with_backup (TOCTOU & Symlink Protected)
// -----------------------------------------------------------------------------

use std::sync::atomic::{AtomicU64, Ordering};
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Metadata result of an atomic write operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicWriteResult {
    pub target_path: PathBuf,
    pub bytes_written: usize,
    pub backup_path: Option<PathBuf>,
}

/// Safely writes content to `target_path` atomically using a temporary file in the same
/// directory, syncs data to physical storage, prevents symlink/TOCTOU substitution,
/// and creates an automated backup if the file already exists.
pub async fn atomic_write_with_backup(
    target_path: &Path,
    content: &[u8],
    create_backup: bool,
) -> Result<AtomicWriteResult, String> {
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() && !parent.exists() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            format!(
                "Failed to create parent directory '{}': {e}",
                parent.display()
            )
        })?;
    }

    let canonical_parent = tokio::fs::canonicalize(parent).await.map_err(|e| {
        format!(
            "Failed to canonicalize parent directory '{}': {e}",
            parent.display()
        )
    })?;

    if !canonical_parent.is_dir() {
        return Err(format!(
            "Parent path '{}' is not a directory",
            parent.display()
        ));
    }

    let mut backup_path_opt = None;
    let mut existing_permissions = None;
    match tokio::fs::symlink_metadata(target_path).await {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Security Violation: Target path '{}' is a symlink, which is prohibited to prevent symlink/TOCTOU attacks",
                    target_path.display()
                ));
            }
            if meta.is_dir() {
                return Err(format!(
                    "Target path '{}' is a directory, not a regular file",
                    target_path.display()
                ));
            }
            existing_permissions = Some(meta.permissions());
            if create_backup {
                let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
                let mut candidate_backup =
                    PathBuf::from(format!("{}.bak.{}", target_path.display(), timestamp));
                let mut counter = 1;
                while tokio::fs::symlink_metadata(&candidate_backup).await.is_ok() {
                    candidate_backup = PathBuf::from(format!(
                        "{}.bak.{}_{}",
                        target_path.display(),
                        timestamp,
                        counter
                    ));
                    counter += 1;
                }
                tokio::fs::copy(target_path, &candidate_backup)
                    .await
                    .map_err(|e| {
                        format!(
                            "Failed to create backup at '{}': {e}",
                            candidate_backup.display()
                        )
                    })?;
                backup_path_opt = Some(candidate_backup);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Target does not exist yet; no backup needed
        }
        Err(e) => {
            return Err(format!(
                "Cannot inspect target file '{}': {e}",
                target_path.display()
            ));
        }
    }

    let cnt = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp_nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let temp_name = format!(".tmp_{}_{}_{cnt}.tmp", std::process::id(), timestamp_nanos);
    let temp_path = parent.join(temp_name);

    let mut temp_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .await
        .map_err(|e| {
            format!(
                "Failed to create temporary file '{}': {e}",
                temp_path.display()
            )
        })?;

    if let Some(permissions) = existing_permissions {
        tokio::fs::set_permissions(&temp_path, permissions)
            .await
            .map_err(|e| format!("Failed to preserve target permissions on temporary file: {e}"))?;
    }

    use tokio::io::AsyncWriteExt;
    let write_res: Result<(), std::io::Error> = async {
        temp_file.write_all(content).await?;
        temp_file.flush().await?;
        temp_file.sync_all().await?;
        Ok(())
    }
    .await;

    // Explicitly drop handle so Windows allows file renaming
    drop(temp_file);

    if let Err(e) = write_res {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(format!(
            "Failed to write data to temporary file '{}': {e}",
            temp_path.display()
        ));
    }

    // TOCTOU check 1: ensure parent directory has not been altered or swapped
    let current_canonical_parent = match tokio::fs::canonicalize(parent).await {
        Ok(p) => p,
        Err(e) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(format!("Parent directory verification failed: {e}"));
        }
    };
    if current_canonical_parent != canonical_parent {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err("Security Violation: Parent directory path was modified during write operation (TOCTOU detected)".to_string());
    }

    // TOCTOU check 2: ensure target path hasn't been substituted with a symlink during write
    if let Ok(meta) = tokio::fs::symlink_metadata(target_path).await
        && meta.file_type().is_symlink()
    {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(format!(
            "Security Violation: Target path '{}' was modified to a symlink during write operation (TOCTOU detected)",
            target_path.display()
        ));
    }

    // Atomic rename
    if let Err(e) = tokio::fs::rename(&temp_path, target_path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(format!(
            "Atomic rename failed from '{}' to '{}': {e}",
            temp_path.display(),
            target_path.display()
        ));
    }

    // Persist the directory entry update as well as the file contents. Directory
    // fsync is required for rename durability on Unix filesystems.
    #[cfg(unix)]
    {
        let parent_dir = tokio::fs::File::open(parent)
            .await
            .map_err(|e| format!("Failed to open parent directory for sync: {e}"))?;
        parent_dir
            .sync_all()
            .await
            .map_err(|e| format!("Failed to sync parent directory after atomic rename: {e}"))?;
    }

    Ok(AtomicWriteResult {
        target_path: target_path.to_path_buf(),
        bytes_written: content.len(),
        backup_path: backup_path_opt,
    })
}

/// Safely writes content to a file with default security configuration.
pub async fn write_file(path_str: &str, content: &str) -> Result<String, String> {
    let default_sec = crate::config::SecurityConfig::default();
    write_file_with_config(path_str, content, &default_sec).await
}

/// Safely writes content to a file with specified SecurityConfig.
/// Strictly forbids overwriting critical system files (/etc/shadow, /etc/passwd, daemon binaries, etc.),
/// ensures atomic replacement and creates automatic backups on overwrite.
pub async fn write_file_with_config(
    path_str: &str,
    content: &str,
    security: &crate::config::SecurityConfig,
) -> Result<String, String> {
    let trimmed = path_str.trim();
    if trimmed.is_empty() {
        return Err("File path cannot be empty".to_string());
    }

    let path = Path::new(trimmed);

    // Security check: verify path is safe to write
    crate::guard::fs_guard::check_file_write_safety_with_config(path, security)
        .map_err(|e| format!("Security Violation: {e}"))?;

    let normalized =
        crate::guard::fs_guard::normalize_path(path).map_err(|e| format!("Invalid path: {e}"))?;

    let result = atomic_write_with_backup(&normalized, content.as_bytes(), true).await?;

    let backup_msg = match result.backup_path {
        Some(ref b) => format!(" (backup created: '{}')", b.display()),
        None => String::new(),
    };

    Ok(format!(
        "Successfully wrote {} bytes to '{}'{}",
        result.bytes_written,
        normalized.display(),
        backup_msg
    ))
}

// -----------------------------------------------------------------------------
// 4. search_files
// -----------------------------------------------------------------------------

/// Searches for files by name and scans text file contents for a pattern.
/// Returns a JSON-formatted array of [`SearchMatch`].
pub async fn search_files(path_str: &str, pattern: &str) -> Result<String, String> {
    let trimmed_path = path_str.trim();
    if trimmed_path.is_empty() {
        return Err("Search path cannot be empty".to_string());
    }

    let trimmed_pattern = pattern.trim();
    if trimmed_pattern.is_empty() {
        return Err("Search pattern cannot be empty".to_string());
    }

    let root_path = Path::new(trimmed_path);
    let normalized = crate::guard::fs_guard::normalize_path(root_path)
        .map_err(|e| format!("Invalid search path: {e}"))?;

    let meta = tokio::fs::metadata(&normalized)
        .await
        .map_err(|e| format!("Cannot access path '{}': {e}", normalized.display()))?;

    if !meta.is_dir() {
        return Err(format!(
            "Search root '{}' is not a directory",
            normalized.display()
        ));
    }

    let pattern_lower = trimmed_pattern.to_lowercase();
    let mut matches = Vec::new();

    collect_search_matches(&normalized, 1, 5, &pattern_lower, &mut matches).await?;

    serde_json::to_string_pretty(&matches)
        .map_err(|e| format!("Failed to serialize search results: {e}"))
}

async fn collect_search_matches(
    dir: &Path,
    current_depth: usize,
    max_depth: usize,
    pattern_lower: &str,
    matches: &mut Vec<SearchMatch>,
) -> Result<(), String> {
    if matches.len() >= 50 {
        return Ok(());
    }

    // Skip virtual or kernel pseudo-filesystems
    let dir_str = dir.to_string_lossy().replace('\\', "/").to_lowercase();
    if dir_str.starts_with("/proc") || dir_str.starts_with("/sys") || dir_str.starts_with("/dev") {
        return Ok(());
    }

    let mut read_dir = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        if matches.len() >= 50 {
            break;
        }

        let entry_path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();
        let display_path = entry_path.to_string_lossy().replace('\\', "/");

        // 1. Filename match
        if file_name.to_lowercase().contains(pattern_lower) {
            matches.push(SearchMatch {
                path: display_path.clone(),
                match_type: "filename".to_string(),
                line_number: None,
                preview: None,
            });
        }

        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.is_dir() {
            if current_depth < max_depth {
                Box::pin(collect_search_matches(
                    &entry_path,
                    current_depth + 1,
                    max_depth,
                    pattern_lower,
                    matches,
                ))
                .await?;
            }
        } else if meta.is_file() && meta.len() <= 1024 * 1024 {
            // 2. Content match (for files under 1MB)
            // Skip sensitive files
            if crate::guard::fs_guard::check_file_read_safety(&entry_path).is_err() {
                continue;
            }

            if let Ok(bytes) = tokio::fs::read(&entry_path).await {
                let text = String::from_utf8_lossy(&bytes);
                let mut matches_for_this_file = 0;

                for (idx, line) in text.lines().enumerate() {
                    if line.to_lowercase().contains(pattern_lower) {
                        let trimmed_line = line.trim();
                        let preview: String = trimmed_line.chars().take(200).collect();

                        matches.push(SearchMatch {
                            path: display_path.clone(),
                            match_type: "content".to_string(),
                            line_number: Some(idx + 1),
                            preview: Some(preview),
                        });

                        matches_for_this_file += 1;
                        if matches_for_this_file >= 5 || matches.len() >= 50 {
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// 5. tail_logs (Bounded Seek & UTF-8 / Partial Line Discard)
// -----------------------------------------------------------------------------

/// Default maximum bytes scanned from the end of the log file (2 MB).
pub const DEFAULT_MAX_TAIL_BYTES: usize = 2 * 1024 * 1024;

/// Reads the last `lines` lines of a log file (default 50, max 500) using safe bounded seek.
pub async fn tail_logs(path_str: &str, lines: Option<usize>) -> Result<String, String> {
    tail_logs_bounded(path_str, lines, None).await
}

/// Reads the last `lines` lines of a log file bounded by `max_tail_bytes` using `seek(SeekFrom::Start/End)`.
/// Discards the first incomplete line if seeking begins mid-file to avoid corrupt text.
pub async fn tail_logs_bounded(
    path_str: &str,
    lines: Option<usize>,
    max_tail_bytes: Option<usize>,
) -> Result<String, String> {
    let trimmed = path_str.trim();
    if trimmed.is_empty() {
        return Err("Log file path cannot be empty".to_string());
    }

    let path = Path::new(trimmed);

    // Security check
    crate::guard::fs_guard::check_file_read_safety(path)
        .map_err(|e| format!("Security Violation: {e}"))?;

    let normalized =
        crate::guard::fs_guard::normalize_path(path).map_err(|e| format!("Invalid path: {e}"))?;

    let mut file = tokio::fs::File::open(&normalized)
        .await
        .map_err(|e| format!("Cannot access log file '{}': {e}", normalized.display()))?;

    let meta = file
        .metadata()
        .await
        .map_err(|e| format!("Cannot read metadata for '{}': {e}", normalized.display()))?;

    if meta.is_dir() {
        return Err(format!(
            "Path '{}' is a directory, not a log file",
            normalized.display()
        ));
    }

    let file_len = meta.len();
    if file_len == 0 {
        return Ok("[Log file is empty]".to_string());
    }

    let line_limit = lines.unwrap_or(50).clamp(1, 500);
    let max_read_bytes = max_tail_bytes
        .unwrap_or(DEFAULT_MAX_TAIL_BYTES)
        .clamp(1024, 50 * 1024 * 1024) as u64;

    let (seek_offset, is_partial_file) = if file_len > max_read_bytes {
        (file_len - max_read_bytes, true)
    } else {
        (0, false)
    };

    if is_partial_file {
        use std::io::SeekFrom;
        use tokio::io::AsyncSeekExt;
        file.seek(SeekFrom::Start(seek_offset))
            .await
            .map_err(|e| format!("Failed to seek in log file: {e}"))?;
    }

    let bytes_to_read = (file_len - seek_offset) as usize;
    let mut buffer = Vec::with_capacity(bytes_to_read);

    use tokio::io::AsyncReadExt;
    let reader = tokio::io::BufReader::new(file);
    reader
        .take(bytes_to_read as u64)
        .read_to_end(&mut buffer)
        .await
        .map_err(|e| format!("Failed to read log file stream: {e}"))?;

    if buffer.is_empty() {
        return Ok("[Log file is empty]".to_string());
    }

    // Skip leading UTF-8 continuation bytes if read started mid-character
    let mut valid_start = 0;
    if is_partial_file {
        while valid_start < buffer.len() && (buffer[valid_start] & 0b1100_0000) == 0b1000_0000 {
            valid_start += 1;
        }
    }

    let text = String::from_utf8_lossy(&buffer[valid_start..]);

    // Discard the first incomplete line if seeking occurred mid-file
    let text_to_split = if is_partial_file {
        if let Some(pos) = text.find('\n') {
            &text[pos + 1..]
        } else {
            &text[..]
        }
    } else {
        &text[..]
    };

    let all_lines: Vec<&str> = text_to_split.lines().collect();
    if all_lines.is_empty() {
        return Ok(String::new());
    }

    let count = all_lines.len();
    let start_idx = count.saturating_sub(line_limit);
    let tail_slice = &all_lines[start_idx..];

    Ok(tail_slice.join("\n"))
}

// -----------------------------------------------------------------------------
// McpTool Implementations
// -----------------------------------------------------------------------------

use crate::mcp::protocol::CallToolResult;
use crate::tools::registry::{McpTool, ToolContext, ToolRegistry};
use async_trait::async_trait;

pub struct ListDirectoryTool;

#[async_trait]
impl McpTool for ListDirectoryTool {
    fn name(&self) -> &str {
        "list_directory"
    }

    fn description(&self) -> &str {
        "Lists directory contents with deterministic cursor-based pagination, file metadata (size, type, modification time), and depth limiting."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list."
                },
                "max_depth": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5,
                    "description": "Maximum directory traversal depth (default 1, maximum 5)."
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": "Maximum number of entries per page (default 100, maximum 500)."
                },
                "cursor": {
                    "type": "string",
                    "description": "Optional pagination continuation token from previous response to fetch the next page."
                }
            },
            "required": ["path"]
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let path = args.get("path").and_then(|p| p.as_str());
        let max_depth = args
            .get("max_depth")
            .and_then(|d| d.as_u64())
            .map(|d| d as usize);
        let limit = args
            .get("limit")
            .and_then(|l| l.as_u64())
            .map(|l| l as usize);
        let cursor = args.get("cursor").and_then(|c| c.as_str());

        match path {
            Some(p) => match list_directory(p, max_depth, limit, cursor).await {
                Ok(result) => match serde_json::to_string_pretty(&result) {
                    Ok(json) => Ok(CallToolResult::text(json)),
                    Err(e) => Ok(CallToolResult::error(format!("Serialization error: {e}"))),
                },
                Err(e) => Ok(CallToolResult::error(e)),
            },
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'path' must be a string",
            )),
        }
    }
}

pub struct ReadFileTool;

#[async_trait]
impl McpTool for ReadFileTool {
    fn name(&self) -> &str {
        "read_file"
    }

    fn description(&self) -> &str {
        "Safely reads the text content of a file with size limits (default 1MB) and credential protection."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to read."
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Maximum bytes to read (default 1048576 = 1MB)."
                }
            },
            "required": ["path"]
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let path = args.get("path").and_then(|p| p.as_str());
        let max_bytes = args
            .get("max_bytes")
            .and_then(|b| b.as_u64())
            .map(|b| b as usize);

        match path {
            Some(p) => match read_file(p, max_bytes).await {
                Ok(content) => Ok(CallToolResult::text(content)),
                Err(e) => Ok(CallToolResult::error(e)),
            },
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'path' must be a string",
            )),
        }
    }
}

pub struct WriteFileTool;

#[async_trait]
impl McpTool for WriteFileTool {
    fn name(&self) -> &str {
        "write_file"
    }

    fn description(&self) -> &str {
        "Safely writes content to a file with strict protection against overwriting critical system files (/etc/shadow, /etc/passwd, daemon binaries)."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to write."
                },
                "content": {
                    "type": "string",
                    "description": "Text content to write to the file."
                }
            },
            "required": ["path", "content"]
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let path = args.get("path").and_then(|p| p.as_str());
        let content = args.get("content").and_then(|c| c.as_str());

        match (path, content) {
            (Some(p), Some(c)) => match write_file_with_config(p, c, &ctx.config.security).await {
                Ok(msg) => Ok(CallToolResult::text(msg)),
                Err(e) => Ok(CallToolResult::error(e)),
            },
            _ => Ok(CallToolResult::error(
                "Missing required parameters: 'path' (string) and 'content' (string)",
            )),
        }
    }
}

pub struct SearchFilesTool;

#[async_trait]
impl McpTool for SearchFilesTool {
    fn name(&self) -> &str {
        "search_files"
    }

    fn description(&self) -> &str {
        "Searches for files by filename pattern and scans file contents for matching lines (grep/find equivalent)."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Root directory path to search within."
                },
                "pattern": {
                    "type": "string",
                    "description": "Search pattern to look for in file names and text contents."
                }
            },
            "required": ["path", "pattern"]
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let path = args.get("path").and_then(|p| p.as_str());
        let pattern = args.get("pattern").and_then(|pat| pat.as_str());

        match (path, pattern) {
            (Some(p), Some(pat)) => match search_files(p, pat).await {
                Ok(results) => match serde_json::to_string_pretty(&results) {
                    Ok(json) => Ok(CallToolResult::text(json)),
                    Err(e) => Ok(CallToolResult::error(format!("Serialization error: {e}"))),
                },
                Err(e) => Ok(CallToolResult::error(e)),
            },
            _ => Ok(CallToolResult::error(
                "Missing required parameters: 'path' (string) and 'pattern' (string)",
            )),
        }
    }
}

pub struct TailLogsTool;

#[async_trait]
impl McpTool for TailLogsTool {
    fn name(&self) -> &str {
        "tail_logs"
    }

    fn description(&self) -> &str {
        "Reads the last N lines of a log file using bounded seek without loading the whole file into memory."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the log file."
                },
                "lines": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": "Number of trailing lines to return (default 50)."
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1024,
                    "description": "Maximum bytes scanned from the end of the log file (default 2097152 = 2MB)."
                }
            },
            "required": ["path"]
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let path = args.get("path").and_then(|p| p.as_str());
        let lines = args
            .get("lines")
            .and_then(|l| l.as_u64())
            .map(|l| l as usize);
        let max_bytes = args
            .get("max_bytes")
            .and_then(|b| b.as_u64())
            .map(|b| b as usize);

        match path {
            Some(p) => match tail_logs_bounded(p, lines, max_bytes).await {
                Ok(content) => Ok(CallToolResult::text(content)),
                Err(e) => Ok(CallToolResult::error(e)),
            },
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'path' must be a string",
            )),
        }
    }
}

/// Registers the 5 file operation tools into the given registry.
pub fn register_file_ops_tools(registry: &mut ToolRegistry) {
    registry.register_tool(ListDirectoryTool);
    registry.register_tool(ReadFileTool);
    registry.register_tool(WriteFileTool);
    registry.register_tool(SearchFilesTool);
    registry.register_tool(TailLogsTool);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_list_directory_success() {
        let temp_dir = std::env::temp_dir().join(format!("vibe_test_dir_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let sub_dir = temp_dir.join("subdir");
        tokio::fs::create_dir_all(&sub_dir).await.unwrap();

        let file_path = temp_dir.join("sample.txt");
        tokio::fs::write(&file_path, "hello world").await.unwrap();

        let result = list_directory(temp_dir.to_str().unwrap(), Some(2), None, None)
            .await
            .expect("list_directory should succeed");

        assert!(
            result
                .entries
                .iter()
                .any(|e| e.name == "sample.txt" && e.entry_type == "file")
        );
        assert!(
            result
                .entries
                .iter()
                .any(|e| e.name == "subdir" && e.entry_type == "directory")
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_list_directory_pagination_deterministic() {
        let temp_dir = std::env::temp_dir().join(format!("vibe_test_pag_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        // Create 25 files: item_00.txt to item_24.txt
        for i in 0..25 {
            let file_path = temp_dir.join(format!("item_{:02}.txt", i));
            tokio::fs::write(&file_path, format!("content {i}"))
                .await
                .unwrap();
        }

        // Page 1: limit 10
        let page1 = list_directory(temp_dir.to_str().unwrap(), Some(1), Some(10), None)
            .await
            .unwrap();
        assert_eq!(page1.entries.len(), 10);
        assert!(page1.truncated);
        assert!(page1.next_cursor.is_some());
        assert_eq!(page1.entries[0].name, "item_00.txt");
        assert_eq!(page1.entries[9].name, "item_09.txt");

        // Page 2: limit 10 with cursor from page 1
        let cursor1 = page1.next_cursor.as_deref().unwrap();
        let page2 = list_directory(temp_dir.to_str().unwrap(), Some(1), Some(10), Some(cursor1))
            .await
            .unwrap();
        assert_eq!(page2.entries.len(), 10);
        assert!(page2.truncated);
        assert!(page2.next_cursor.is_some());
        assert_eq!(page2.entries[0].name, "item_10.txt");
        assert_eq!(page2.entries[9].name, "item_19.txt");

        // Page 3: limit 10 with cursor from page 2 (remaining 5 items)
        let cursor2 = page2.next_cursor.as_deref().unwrap();
        let page3 = list_directory(temp_dir.to_str().unwrap(), Some(1), Some(10), Some(cursor2))
            .await
            .unwrap();
        assert_eq!(page3.entries.len(), 5);
        assert!(!page3.truncated);
        assert!(page3.next_cursor.is_none());
        assert_eq!(page3.entries[0].name, "item_20.txt");
        assert_eq!(page3.entries[4].name, "item_24.txt");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_list_directory_invalid_cursor_returns_error() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_test_invalid_cur_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let res = list_directory(
            temp_dir.to_str().unwrap(),
            Some(1),
            Some(10),
            Some("invalid_token!"),
        )
        .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Invalid cursor"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_tail_logs_bounded_large_file_and_partial_line_discard() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_test_tail_seek_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let log_file = temp_dir.join("seek_test.log");
        let mut lines = Vec::new();
        for i in 1..=200 {
            lines.push(format!(
                "This is a log line number {:04} with extra text padding to ensure size",
                i
            ));
        }
        let full_text = lines.join("\n");
        tokio::fs::write(&log_file, full_text).await.unwrap();

        // Pass max_tail_bytes = 2048 to force seek into the middle of the large file
        let tailed = tail_logs_bounded(log_file.to_str().unwrap(), Some(5), Some(2048))
            .await
            .unwrap();

        let out_lines: Vec<&str> = tailed.lines().collect();
        assert_eq!(out_lines.len(), 5);
        assert!(out_lines[4].contains("0200"));
        assert!(out_lines[3].contains("0199"));
        assert!(out_lines[2].contains("0198"));
        assert!(out_lines[1].contains("0197"));
        assert!(out_lines[0].contains("0196"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_atomic_write_creates_backup_and_preserves_content() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_test_atomic_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let target_file = temp_dir.join("config.ini");
        let path_str = target_file.to_str().unwrap();

        // 1. Initial write
        let res1 = write_file(path_str, "version=1.0\nmode=production").await;
        assert!(res1.is_ok());

        // 2. Overwrite file
        let res2 = write_file(path_str, "version=2.0\nmode=development").await;
        assert!(res2.is_ok());
        assert!(res2.unwrap().contains("backup created"));

        // Verify target file has updated content
        let current_content = tokio::fs::read_to_string(&target_file).await.unwrap();
        assert_eq!(current_content, "version=2.0\nmode=development");

        // Verify backup exists and contains previous content
        let mut read_dir = tokio::fs::read_dir(&temp_dir).await.unwrap();
        let mut found_backup = false;
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("config.ini.bak.") {
                found_backup = true;
                let backup_content = tokio::fs::read_to_string(entry.path()).await.unwrap();
                assert_eq!(backup_content, "version=1.0\nmode=production");
            }
        }
        assert!(
            found_backup,
            "A backup file must have been created on overwrite"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_read_and_write_file_success() {
        let temp_dir = std::env::temp_dir().join(format!("vibe_test_rw_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let target_file = temp_dir.join("data.txt");
        let path_str = target_file.to_str().unwrap();

        let write_res = write_file(path_str, "alpha beta gamma").await;
        assert!(write_res.is_ok());

        let read_res = read_file(path_str, None).await;
        assert_eq!(read_res.unwrap(), "alpha beta gamma");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_write_file_blocks_etc_shadow() {
        let res = write_file("/etc/shadow", "malicious_content").await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.contains("Security Violation"));
        assert!(err.contains("forbidden"));
    }

    #[tokio::test]
    async fn test_write_file_blocks_etc_passwd() {
        let res = write_file("/etc/passwd", "root:x:0:0:...").await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.contains("Security Violation"));
    }

    #[tokio::test]
    async fn test_write_file_blocks_etc_sudoers() {
        let res = write_file("/etc/sudoers", "ALL ALL=(ALL) NOPASSWD: ALL").await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.contains("Security Violation"));
    }

    #[tokio::test]
    async fn test_read_file_blocks_etc_shadow() {
        let res = read_file("/etc/shadow", None).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Security Violation"));
    }

    #[tokio::test]
    async fn test_read_file_exceeds_max_bytes() {
        let temp_dir = std::env::temp_dir().join(format!("vibe_test_maxb_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let target_file = temp_dir.join("large.txt");
        tokio::fs::write(&target_file, "1234567890abcdefghij")
            .await
            .unwrap();

        let res = read_file(target_file.to_str().unwrap(), Some(5)).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("exceeds maximum allowed limit"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_search_files_finds_name_and_content() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_test_search_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let f1 = temp_dir.join("target_file.txt");
        tokio::fs::write(&f1, "Nothing here").await.unwrap();

        let f2 = temp_dir.join("other.txt");
        tokio::fs::write(&f2, "Here is secret_token_xyz in line 1")
            .await
            .unwrap();

        // 1. Search by filename
        let res_name = search_files(temp_dir.to_str().unwrap(), "target_file")
            .await
            .unwrap();
        let matches_name: Vec<SearchMatch> = serde_json::from_str(&res_name).unwrap();
        assert!(matches_name.iter().any(|m| m.match_type == "filename"));

        // 2. Search by content
        let res_content = search_files(temp_dir.to_str().unwrap(), "secret_token_xyz")
            .await
            .unwrap();
        let matches_content: Vec<SearchMatch> = serde_json::from_str(&res_content).unwrap();
        assert!(
            matches_content
                .iter()
                .any(|m| m.match_type == "content" && m.line_number == Some(1))
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_tail_logs_returns_last_n_lines() {
        let temp_dir = std::env::temp_dir().join(format!("vibe_test_tail_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let log_file = temp_dir.join("app.log");
        let lines: Vec<String> = (1..=20).map(|i| format!("line {i}")).collect();
        tokio::fs::write(&log_file, lines.join("\n")).await.unwrap();

        let tailed = tail_logs(log_file.to_str().unwrap(), Some(5))
            .await
            .unwrap();
        let out_lines: Vec<&str> = tailed.lines().collect();
        assert_eq!(out_lines.len(), 5);
        assert_eq!(out_lines[0], "line 16");
        assert_eq!(out_lines[4], "line 20");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_tail_logs_empty_file() {
        let temp_dir =
            std::env::temp_dir().join(format!("vibe_test_tail_empty_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let log_file = temp_dir.join("empty.log");
        tokio::fs::write(&log_file, "").await.unwrap();

        let res = tail_logs(log_file.to_str().unwrap(), Some(10))
            .await
            .unwrap();
        assert_eq!(res, "[Log file is empty]");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
