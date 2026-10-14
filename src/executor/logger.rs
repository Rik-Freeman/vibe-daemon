//! Smart Log Engine: log compression, error extraction, and line deduplication.
//! Suppresses noisy success logs to save AI context tokens, while extracting
//! actionable panic messages, compiler errors, and contextual failure stacktraces.

use std::collections::BTreeSet;

/// Deduplicate consecutive identical lines into `[Repeated N times] <line>`.
pub fn deduplicate_lines(lines: &[&str]) -> Vec<String> {
    if lines.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut current_line = lines[0];
    let mut count = 1usize;

    for &line in &lines[1..] {
        if line == current_line {
            count += 1;
        } else {
            if count > 1 {
                result.push(format!("[Repeated {count} times] {current_line}"));
            } else {
                result.push(current_line.to_string());
            }
            current_line = line;
            count = 1;
        }
    }

    if count > 1 {
        result.push(format!("[Repeated {count} times] {current_line}"));
    } else {
        result.push(current_line.to_string());
    }

    result
}

/// Analyze process output and generate a compressed, token-efficient report.
pub fn compress_output(
    exit_code: Option<i32>,
    duration_secs: f64,
    stdout: &str,
    stderr: &str,
) -> String {
    let is_success = exit_code == Some(0);

    if is_success {
        compress_success_output(duration_secs, stdout, stderr)
    } else {
        compress_error_output(exit_code, duration_secs, stdout, stderr)
    }
}

/// Compress successful output by suppressing long repetitive text and preserving tail context.
fn compress_success_output(duration_secs: f64, stdout: &str, stderr: &str) -> String {
    // Combine non-empty streams (stdout preferred for output, stderr if stdout empty)
    let raw_text = if !stdout.trim().is_empty() {
        stdout
    } else if !stderr.trim().is_empty() {
        stderr
    } else {
        ""
    };

    let raw_lines: Vec<&str> = raw_text.lines().map(|l| l.trim_end()).collect();
    let deduped = deduplicate_lines(&raw_lines);

    // If output is short (e.g. 1 to 5 lines and < 300 chars), display it directly
    if deduped.len() <= 5 && raw_text.len() <= 300 {
        if deduped.is_empty() {
            return format!("SUCCESS: Command completed in {duration_secs:.2}s. [No output]");
        }
        let joined = deduped.join("\n");
        return format!("SUCCESS: Command completed in {duration_secs:.2}s.\n{joined}");
    }

    // Long output: suppress the bulk, preserving the last 5-10 useful lines
    let keep_count = deduped.len().min(8);
    let tail_lines = &deduped[deduped.len() - keep_count..];
    let tail_text = tail_lines.join("\n");

    format!(
        "SUCCESS: Command completed in {duration_secs:.2}s. [Output suppressed, no errors detected]\n--- Last {keep_count} lines ---\n{tail_text}"
    )
}

/// Compress failure output by extracting panics, compiler errors, and the last 15-20 lines of context.
fn compress_error_output(
    exit_code: Option<i32>,
    duration_secs: f64,
    stdout: &str,
    stderr: &str,
) -> String {
    let mut combined_lines = Vec::new();

    // In Rust / Cargo, compilation and runtime errors can be in either stderr or stdout
    for line in stdout.lines() {
        combined_lines.push(line.trim_end());
    }
    for line in stderr.lines() {
        combined_lines.push(line.trim_end());
    }

    let deduped = deduplicate_lines(&combined_lines);
    let code_str = exit_code.map_or("unknown".to_string(), |c| c.to_string());

    if deduped.is_empty() {
        return format!(
            "FAILED: Command exited with code {code_str} in {duration_secs:.2}s. [No output]"
        );
    }

    // If total lines are short (<= 20), return all lines deduplicated
    if deduped.len() <= 20 {
        let content = deduped.join("\n");
        return format!(
            "FAILED: Command exited with code {code_str} in {duration_secs:.2}s.\n{content}"
        );
    }

    // Identify indices of critical error markers
    let error_signatures = [
        "panicked at",
        "error[e",
        "error:",
        "failed",
        "failures:",
        "fatal:",
        "traceback (most recent call last):",
        "exception:",
        "stack backtrace:",
    ];

    let mut selected_indices = BTreeSet::new();

    for (i, line) in deduped.iter().enumerate() {
        let lower = line.to_lowercase();
        if error_signatures.iter().any(|&sig| lower.contains(sig)) {
            // Include 2 lines of preceding context and up to 8 lines of following context
            let start = i.saturating_sub(2);
            let end = (i + 8).min(deduped.len() - 1);
            for idx in start..=end {
                selected_indices.insert(idx);
            }
        }
    }

    // Always include the last 15 lines of context
    let tail_start = deduped.len().saturating_sub(15);
    for idx in tail_start..deduped.len() {
        selected_indices.insert(idx);
    }

    // Build the pruned output
    let mut extracted = Vec::new();
    let mut last_idx: Option<usize> = None;

    for &idx in &selected_indices {
        if let Some(prev) = last_idx
            && idx > prev + 1
        {
            extracted.push(format!("... [{} lines omitted] ...", idx - prev - 1));
        }
        extracted.push(deduped[idx].clone());
        last_idx = Some(idx);
    }

    let details = extracted.join("\n");
    format!(
        "FAILED: Command exited with code {code_str} in {duration_secs:.2}s.\n=== Extracted Error Details ===\n{details}"
    )
}

/// Compress journalctl / system service logs using Smart Log Engine.
/// Deduplicates consecutive repetitive lines, prioritizes error/warning signatures,
/// and produces clean, token-efficient output.
pub fn compress_journal_logs(raw_logs: &str, service_name: &str) -> String {
    let trimmed = raw_logs.trim();
    if trimmed.is_empty() {
        return format!("Logs for service '{service_name}': [No log entries found]");
    }

    let lines: Vec<&str> = trimmed.lines().map(|l| l.trim_end()).collect();
    let deduped = deduplicate_lines(&lines);

    if deduped.is_empty() {
        return format!("Logs for service '{service_name}': [No log entries found]");
    }

    // If short (<= 25 lines), return all deduplicated lines directly
    if deduped.len() <= 25 {
        return format!(
            "Logs for service '{service_name}' ({} lines):\n{}",
            deduped.len(),
            deduped.join("\n")
        );
    }

    // Scan for error markers
    let error_signatures = [
        "error",
        "failed",
        "failures",
        "fatal",
        "panic",
        "exception",
        "critical",
        "warn",
        "warning",
        "emerg",
        "alert",
    ];

    let mut selected_indices = BTreeSet::new();

    for (i, line) in deduped.iter().enumerate() {
        let lower = line.to_lowercase();
        if error_signatures.iter().any(|&sig| lower.contains(sig)) {
            let start = i.saturating_sub(1);
            let end = (i + 2).min(deduped.len() - 1);
            for idx in start..=end {
                selected_indices.insert(idx);
            }
        }
    }

    // Always include the last 15 lines of context
    let tail_start = deduped.len().saturating_sub(15);
    for idx in tail_start..deduped.len() {
        selected_indices.insert(idx);
    }

    let has_early_errors = selected_indices.iter().any(|&idx| idx < tail_start);

    let mut extracted = Vec::new();
    let mut last_idx: Option<usize> = None;

    for &idx in &selected_indices {
        if let Some(prev) = last_idx
            && idx > prev + 1
        {
            extracted.push(format!("... [{} lines omitted] ...", idx - prev - 1));
        }
        extracted.push(deduped[idx].clone());
        last_idx = Some(idx);
    }

    let details = extracted.join("\n");
    if has_early_errors {
        format!(
            "Logs for service '{service_name}' ({} total lines, compressed with extracted errors and recent tail):\n{details}",
            deduped.len()
        )
    } else {
        format!(
            "Logs for service '{service_name}' ({} total lines, no critical early errors, displaying recent tail):\n{details}",
            deduped.len()
        )
    }
}

/// Compress container logs (from `docker logs`) using Smart Log Engine.
/// Deduplicates repetitive heartbeat entries, prioritizes error/exception signatures,
/// and provides token-efficient log reporting.
pub fn compress_container_logs(raw_logs: &str, container_id: &str) -> String {
    let trimmed = raw_logs.trim();
    if trimmed.is_empty() {
        return format!("Logs for container '{container_id}': [No log entries found]");
    }

    let lines: Vec<&str> = trimmed.lines().map(|l| l.trim_end()).collect();
    let deduped = deduplicate_lines(&lines);

    if deduped.is_empty() {
        return format!("Logs for container '{container_id}': [No log entries found]");
    }

    // If short (<= 25 lines), return all deduplicated lines directly
    if deduped.len() <= 25 {
        return format!(
            "Logs for container '{container_id}' ({} lines):\n{}",
            deduped.len(),
            deduped.join("\n")
        );
    }

    // Scan for critical error markers
    let error_signatures = [
        "error",
        "failed",
        "failures",
        "fatal",
        "panic",
        "exception",
        "critical",
        "warn",
        "warning",
        "emerg",
        "alert",
        "traceback",
        "segfault",
    ];

    let mut selected_indices = BTreeSet::new();

    for (i, line) in deduped.iter().enumerate() {
        let lower = line.to_lowercase();
        if error_signatures.iter().any(|&sig| lower.contains(sig)) {
            let start = i.saturating_sub(1);
            let end = (i + 2).min(deduped.len() - 1);
            for idx in start..=end {
                selected_indices.insert(idx);
            }
        }
    }

    // Always include the last 15 lines of context
    let tail_start = deduped.len().saturating_sub(15);
    for idx in tail_start..deduped.len() {
        selected_indices.insert(idx);
    }

    let has_early_errors = selected_indices.iter().any(|&idx| idx < tail_start);

    let mut extracted = Vec::new();
    let mut last_idx: Option<usize> = None;

    for &idx in &selected_indices {
        if let Some(prev) = last_idx
            && idx > prev + 1
        {
            extracted.push(format!("... [{} lines omitted] ...", idx - prev - 1));
        }
        extracted.push(deduped[idx].clone());
        last_idx = Some(idx);
    }

    let details = extracted.join("\n");
    if has_early_errors {
        format!(
            "Logs for container '{container_id}' ({} total lines, compressed with extracted errors and recent tail):\n{details}",
            deduped.len()
        )
    } else {
        format!(
            "Logs for container '{container_id}' ({} total lines, no critical early errors, displaying recent tail):\n{details}",
            deduped.len()
        )
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplicate_consecutive_lines() {
        let input = vec![
            "warning: unused variable `x`",
            "warning: unused variable `x`",
            "warning: unused variable `x`",
            "warning: unused variable `y`",
            "Compiling foo v0.1.0",
            "Compiling foo v0.1.0",
        ];

        let result = deduplicate_lines(&input);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "[Repeated 3 times] warning: unused variable `x`");
        assert_eq!(result[1], "warning: unused variable `y`");
        assert_eq!(result[2], "[Repeated 2 times] Compiling foo v0.1.0");
    }

    #[test]
    fn test_compress_success_short() {
        let output = compress_output(Some(0), 0.05, "Hello World\n", "");
        assert!(output.contains("SUCCESS: Command completed in 0.05s."));
        assert!(output.contains("Hello World"));
        assert!(!output.contains("[Output suppressed"));
    }

    #[test]
    fn test_compress_success_long_suppression() {
        let mut long_stdout = String::new();
        for i in 1..=50 {
            long_stdout.push_str(&format!("test module::test_{i} ... ok\n"));
        }
        long_stdout.push_str("test result: ok. 50 passed; 0 failed; finished in 1.20s\n");

        let compressed = compress_output(Some(0), 1.23, &long_stdout, "");
        assert!(compressed.contains(
            "SUCCESS: Command completed in 1.23s. [Output suppressed, no errors detected]"
        ));
        assert!(compressed.contains("test result: ok. 50 passed"));
        // Early passing lines should be suppressed
        assert!(!compressed.contains("test module::test_1 ... ok"));
    }

    #[test]
    fn test_compress_error_panic_extraction() {
        let mut long_log = String::new();
        for i in 1..=40 {
            long_log.push_str(&format!("test module::test_{i} ... ok\n"));
        }
        long_log.push_str("test module::test_panic ... FAILED\n");
        long_log.push_str("failures:\n");
        long_log.push_str("---- module::test_panic stdout ----\n");
        long_log.push_str(
            "thread 'module::test_panic' panicked at 'index out of bounds', src/main.rs:45:10\n",
        );
        long_log.push_str("stack backtrace:\n");
        long_log.push_str("   0: std::panicking::begin_panic\n");
        for _ in 0..10 {
            long_log.push_str("warning: unused import\n");
        }
        long_log.push_str("failures:\n    module::test_panic\n");
        long_log.push_str("test result: FAILED. 40 passed; 1 failed;\n");

        let compressed = compress_output(Some(101), 2.50, &long_log, "");
        assert!(compressed.contains("FAILED: Command exited with code 101 in 2.50s."));
        assert!(compressed.contains("panicked at 'index out of bounds'"));
        assert!(compressed.contains("test result: FAILED"));
        // Repetitive warnings should be deduplicated
        assert!(compressed.contains("[Repeated 10 times] warning: unused import"));
        // Earlier successful tests should be omitted
        assert!(!compressed.contains("test module::test_1 ... ok"));
    }

    #[test]
    fn test_compress_error_compiler_error() {
        let mut build_log = String::new();
        for i in 1..=30 {
            build_log.push_str(&format!("   Compiling dep_{i} v1.0.0\n"));
        }
        build_log.push_str("error[E0425]: cannot find value `foo` in this scope\n");
        build_log.push_str("  --> src/main.rs:10:5\n");
        build_log.push_str("   |\n10 |     foo\n   |     ^^^ not found in this scope\n");
        build_log.push_str("error: could not compile `vibe-daemon` due to 1 previous error\n");

        let compressed = compress_output(Some(1), 0.85, &build_log, "");
        assert!(compressed.contains("FAILED: Command exited with code 1 in 0.85s."));
        assert!(compressed.contains("error[E0425]: cannot find value `foo` in this scope"));
        assert!(compressed.contains("error: could not compile `vibe-daemon`"));
        assert!(!compressed.contains("Compiling dep_1 v1.0.0"));
    }

    #[test]
    fn test_compress_journal_logs_empty() {
        let res = compress_journal_logs("", "nginx");
        assert_eq!(res, "Logs for service 'nginx': [No log entries found]");
    }

    #[test]
    fn test_compress_journal_logs_short_and_dedup() {
        let logs = "Oct 14 00:00:01 host nginx[100]: worker started\n\
                    Oct 14 00:00:02 host nginx[100]: health check ping\n\
                    Oct 14 00:00:02 host nginx[100]: health check ping\n\
                    Oct 14 00:00:02 host nginx[100]: health check ping\n\
                    Oct 14 00:00:05 host nginx[100]: connection accepted";

        let compressed = compress_journal_logs(logs, "nginx");
        assert!(compressed.contains("Logs for service 'nginx' (3 lines):"));
        assert!(
            compressed
                .contains("[Repeated 3 times] Oct 14 00:00:02 host nginx[100]: health check ping")
        );
        assert!(compressed.contains("worker started"));
        assert!(compressed.contains("connection accepted"));
    }

    #[test]
    fn test_compress_journal_logs_extracts_early_errors() {
        let mut long_log = String::new();
        for i in 1..=15 {
            long_log.push_str(&format!(
                "Oct 14 00:0{i:02}:00 host srv[10]: routine check ok\n"
            ));
        }
        long_log.push_str(
            "Oct 14 00:16:00 host srv[10]: CRITICAL: database connection failed with timeout\n",
        );
        long_log.push_str("Oct 14 00:16:01 host srv[10]: stack backtrace: connection dropped\n");
        for i in 17..=45 {
            long_log.push_str(&format!(
                "Oct 14 00:{i:02}:00 host srv[10]: heart beat ping\n"
            ));
        }

        let compressed = compress_journal_logs(&long_log, "srv");
        assert!(compressed.contains("CRITICAL: database connection failed with timeout"));
        assert!(compressed.contains("stack backtrace: connection dropped"));
        assert!(compressed.contains("compressed with extracted errors and recent tail"));
        assert!(compressed.contains("... ["));
        assert!(compressed.contains("heart beat ping"));
    }

    #[test]
    fn test_compress_container_logs_empty() {
        let res = compress_container_logs("", "c123");
        assert_eq!(res, "Logs for container 'c123': [No log entries found]");
    }

    #[test]
    fn test_compress_container_logs_short_and_dedup() {
        let logs = "2026-10-14T00:00:01Z [info] server listening on :80\n\
                    2026-10-14T00:00:02Z [debug] keepalive ping\n\
                    2026-10-14T00:00:02Z [debug] keepalive ping\n\
                    2026-10-14T00:00:02Z [debug] keepalive ping\n\
                    2026-10-14T00:00:03Z [info] request handled";

        let compressed = compress_container_logs(logs, "web");
        assert!(compressed.contains("Logs for container 'web' (3 lines):"));
        assert!(
            compressed.contains("[Repeated 3 times] 2026-10-14T00:00:02Z [debug] keepalive ping")
        );
        assert!(compressed.contains("server listening on :80"));
    }
}
