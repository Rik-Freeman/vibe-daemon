//! System monitoring module for vibe-daemon.
//! Provides specialized tools for real-time resource inspection:
//! disk usage, CPU & load average, top processes, network interface statistics,
//! and journalctl service logs with Smart Log Engine compression.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tracing::warn;

// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------

/// Disk usage metrics for a mounted filesystem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskUsage {
    pub filesystem: String,
    pub total: String,
    pub used: String,
    pub available: String,
    pub use_percent: String,
    pub mounted_on: String,
}

/// System CPU load average over 1, 5, and 15 minutes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoadAverage {
    pub one_minute: f64,
    pub five_minute: f64,
    pub fifteen_minute: f64,
}

/// Host CPU information including load average and utilization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CpuInfo {
    pub load_average: LoadAverage,
    pub cpu_count: usize,
    pub cpu_utilization_percent: f64,
}

/// Information about a resource-consuming system process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f64,
    pub memory_percent: f64,
}

/// Network statistics for a specific interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceStats {
    pub interface: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

/// Comprehensive network statistics across interfaces and connections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkStats {
    pub interfaces: Vec<InterfaceStats>,
    pub active_tcp_connections: usize,
    pub listening_ports_count: usize,
}

// -----------------------------------------------------------------------------
// Pure Parsers & Logic
// -----------------------------------------------------------------------------

/// Parse `df -h` command output into a list of [`DiskUsage`].
pub fn parse_df_output(output: &str) -> Vec<DiskUsage> {
    let mut results = Vec::new();
    let mut pending_fs: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Skip header lines
        let lower = trimmed.to_lowercase();
        if lower.starts_with("filesystem")
            || lower.starts_with("файловая")
            || lower.starts_with("sys. de fichiers")
            || lower.contains("use%")
            || lower.contains("использ")
        {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();

        // Handle case where filesystem name is long and on its own line
        if parts.len() == 1 {
            pending_fs = Some(parts[0].to_string());
            continue;
        }

        if let Some(fs) = pending_fs.take() {
            if parts.len() >= 5 {
                let total = parts[0].to_string();
                let used = parts[1].to_string();
                let available = parts[2].to_string();
                let use_percent = parts[3].to_string();
                let mounted_on = parts[4..].join(" ");

                results.push(DiskUsage {
                    filesystem: fs,
                    total,
                    used,
                    available,
                    use_percent,
                    mounted_on,
                });
            }
        } else if parts.len() >= 6 {
            let filesystem = parts[0].to_string();
            let total = parts[1].to_string();
            let used = parts[2].to_string();
            let available = parts[3].to_string();
            let use_percent = parts[4].to_string();
            let mounted_on = parts[5..].join(" ");

            results.push(DiskUsage {
                filesystem,
                total,
                used,
                available,
                use_percent,
                mounted_on,
            });
        }
    }

    results
}

/// Parse Linux `/proc/loadavg` content into [`LoadAverage`].
pub fn parse_proc_loadavg(content: &str) -> Option<LoadAverage> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let one_minute = parts[0].parse::<f64>().ok()?;
    let five_minute = parts[1].parse::<f64>().ok()?;
    let fifteen_minute = parts[2].parse::<f64>().ok()?;

    Some(LoadAverage {
        one_minute,
        five_minute,
        fifteen_minute,
    })
}

/// Parse the summary "cpu" line from Linux `/proc/stat`.
/// Returns `Some((idle_jiffies, total_jiffies))`.
pub fn parse_proc_stat_cpu_line(line: &str) -> Option<(u64, u64)> {
    let mut parts = line.split_whitespace();
    let label = parts.next()?;
    if label != "cpu" {
        return None;
    }

    let numbers: Vec<u64> = parts.filter_map(|p| p.parse::<u64>().ok()).collect();
    if numbers.len() < 4 {
        return None;
    }

    let total: u64 = numbers.iter().sum();
    // Idle is field index 3 (4th item), iowait is index 4 (5th item if present)
    let idle = numbers[3] + numbers.get(4).copied().unwrap_or(0);

    Some((idle, total))
}

/// Calculate CPU utilization percentage between two `/proc/stat` readings.
pub fn calculate_cpu_utilization(first: (u64, u64), second: (u64, u64)) -> f64 {
    let (idle1, total1) = first;
    let (idle2, total2) = second;

    let delta_total = total2.saturating_sub(total1);
    let delta_idle = idle2.saturating_sub(idle1);

    if delta_total == 0 {
        return 0.0;
    }

    let busy = delta_total.saturating_sub(delta_idle);
    let pct = (busy as f64 / delta_total as f64) * 100.0;
    (pct * 100.0).round() / 100.0
}

/// Parse `ps -eo pid,comm,%cpu,%mem` output into a list of [`ProcessInfo`].
pub fn parse_ps_output(output: &str) -> Vec<ProcessInfo> {
    let mut processes = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        // Skip header lines
        if parts[0].eq_ignore_ascii_case("pid") || parts.iter().any(|&p| p == "%CPU" || p == "%MEM")
        {
            continue;
        }

        let Ok(pid) = parts[0].parse::<u32>() else {
            continue;
        };

        // Last two items are %CPU and %MEM
        let cpu_str = parts[parts.len() - 2].replace(',', ".");
        let mem_str = parts[parts.len() - 1].replace(',', ".");

        let cpu_percent = cpu_str.parse::<f64>().unwrap_or(0.0);
        let memory_percent = mem_str.parse::<f64>().unwrap_or(0.0);

        // Process name might contain spaces
        let name = parts[1..parts.len() - 2].join(" ");

        processes.push(ProcessInfo {
            pid,
            name,
            cpu_percent,
            memory_percent,
        });
    }

    processes
}

/// Parse Linux `/proc/net/dev` output into a list of [`InterfaceStats`].
pub fn parse_proc_net_dev(content: &str) -> Vec<InterfaceStats> {
    let mut list = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Inter-") || trimmed.starts_with("face") {
            continue;
        }

        let Some((iface_part, stats_part)) = trimmed.split_once(':') else {
            continue;
        };

        let interface = iface_part.trim().to_string();
        let numbers: Vec<u64> = stats_part
            .split_whitespace()
            .filter_map(|p| p.parse::<u64>().ok())
            .collect();

        if numbers.len() >= 16 {
            list.push(InterfaceStats {
                interface,
                rx_bytes: numbers[0],
                rx_packets: numbers[1],
                rx_errors: numbers[2],
                rx_dropped: numbers[3],
                tx_bytes: numbers[8],
                tx_packets: numbers[9],
                tx_errors: numbers[10],
                tx_dropped: numbers[11],
            });
        }
    }

    list
}

/// Count established TCP connections from Linux `/proc/net/tcp` and `/proc/net/tcp6`.
pub fn count_established_tcp_connections(proc_net_tcp: &str) -> usize {
    let mut count = 0;
    for line in proc_net_tcp.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Column 3 (0-indexed) is the connection state in hex: "01" is TCP_ESTABLISHED
        if parts.len() > 3 && parts[3] == "01" {
            count += 1;
        }
    }
    count
}

// -----------------------------------------------------------------------------
// Tool Implementations
// -----------------------------------------------------------------------------

/// Inspect mounted filesystems and available disk space using default security config.
pub async fn get_disk_usage(path: Option<&str>) -> Result<String, String> {
    let default_sec = crate::config::SecurityConfig::default();
    get_disk_usage_with_config(path, &default_sec).await
}

/// Inspect mounted filesystems and available disk space with path verification.
pub async fn get_disk_usage_with_config(
    path: Option<&str>,
    _security: &crate::config::SecurityConfig,
) -> Result<String, String> {
    // 1. Verify path if provided
    let checked_path = if let Some(p) = path {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            let normalized = crate::guard::fs_guard::normalize_path(Path::new(trimmed))
                .map_err(|e| format!("Security Violation: {e}"))?;
            Some(normalized)
        } else {
            None
        }
    } else {
        None
    };

    // 2. Try running `df -h` (standard on Linux/macOS/BSD)
    let mut cmd = tokio::process::Command::new("df");
    cmd.arg("-h");
    if let Some(ref p) = checked_path {
        cmd.arg(p.as_os_str());
    }

    if let Some(stdout) = crate::executor::execute_quick_process(cmd, 5).await {
        let disks = parse_df_output(&stdout);
        return serde_json::to_string_pretty(&disks)
            .map_err(|e| format!("Serialization error: {e}"));
    }

    // 3. Fallback for Windows systems: query via PowerShell
    if cfg!(windows) {
        let ps_cmd = "Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free, Root | ConvertTo-Json";
        let mut ps = tokio::process::Command::new("powershell");
        ps.args(["-Command", ps_cmd]);
        if let Some(stdout) = crate::executor::execute_quick_process(ps, 5).await
            && let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout)
        {
            let items = if val.is_array() {
                val.as_array().cloned().unwrap_or_default()
            } else if val.is_object() {
                vec![val]
            } else {
                Vec::new()
            };

            let mut disks = Vec::new();
            for item in items {
                let name = item["Name"].as_str().unwrap_or("Drive").to_string();
                let root = item["Root"].as_str().unwrap_or("").to_string();
                let used_bytes = item["Used"].as_f64().unwrap_or(0.0);
                let free_bytes = item["Free"].as_f64().unwrap_or(0.0);
                let total_bytes = used_bytes + free_bytes;

                let used_gb = used_bytes / 1_073_741_824.0;
                let free_gb = free_bytes / 1_073_741_824.0;
                let total_gb = total_bytes / 1_073_741_824.0;
                let pct = if total_bytes > 0.0 {
                    (used_bytes / total_bytes) * 100.0
                } else {
                    0.0
                };

                disks.push(DiskUsage {
                    filesystem: name,
                    total: format!("{total_gb:.1} GB"),
                    used: format!("{used_gb:.1} GB"),
                    available: format!("{free_gb:.1} GB"),
                    use_percent: format!("{pct:.0}%"),
                    mounted_on: root,
                });
            }

            if let Some(ref target) = checked_path {
                let target_str = target.to_string_lossy().to_lowercase();
                disks.retain(|d| {
                    let mount = d.mounted_on.to_lowercase();
                    target_str.starts_with(&mount) || mount.starts_with(&target_str)
                });
            }

            return serde_json::to_string_pretty(&disks)
                .map_err(|e| format!("Serialization error: {e}"));
        }
    }

    // Default fallback if host utilities are unavailable
    let fallback = vec![DiskUsage {
        filesystem: "rootfs".to_string(),
        total: "unknown".to_string(),
        used: "unknown".to_string(),
        available: "unknown".to_string(),
        use_percent: "0%".to_string(),
        mounted_on: "/".to_string(),
    }];
    serde_json::to_string_pretty(&fallback).map_err(|e| format!("Serialization error: {e}"))
}

/// Collect CPU metrics and load averages.
pub async fn get_cpu_info() -> Result<String, String> {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // 1. Linux /proc implementation
    if let Ok(loadavg_content) = tokio::fs::read_to_string("/proc/loadavg").await
        && let Some(load_avg) = parse_proc_loadavg(&loadavg_content)
    {
        let mut cpu_utilization = 0.0;
        if let Ok(stat1) = tokio::fs::read_to_string("/proc/stat").await
            && let Some(line1) = stat1.lines().next()
            && let Some(sample1) = parse_proc_stat_cpu_line(line1)
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(stat2) = tokio::fs::read_to_string("/proc/stat").await
                && let Some(line2) = stat2.lines().next()
                && let Some(sample2) = parse_proc_stat_cpu_line(line2)
            {
                cpu_utilization = calculate_cpu_utilization(sample1, sample2);
            }
        }

        let info = CpuInfo {
            load_average: load_avg,
            cpu_count,
            cpu_utilization_percent: cpu_utilization,
        };

        return serde_json::to_string_pretty(&info)
            .map_err(|e| format!("Serialization error: {e}"));
    }

    // 2. Windows fallback
    if cfg!(windows) {
        let ps_cmd = "(Get-CimInstance Win32_Processor).LoadPercentage";
        let mut ps = tokio::process::Command::new("powershell");
        ps.args(["-Command", ps_cmd]);
        if let Some(stdout) = crate::executor::execute_quick_process(ps, 5).await {
            let first_line = stdout.lines().next().unwrap_or("0").trim();
            let util = first_line.parse::<f64>().unwrap_or(0.0);
            let approx_load = (util / 100.0) * (cpu_count as f64);

            let info = CpuInfo {
                load_average: LoadAverage {
                    one_minute: (approx_load * 100.0).round() / 100.0,
                    five_minute: (approx_load * 100.0).round() / 100.0,
                    fifteen_minute: (approx_load * 100.0).round() / 100.0,
                },
                cpu_count,
                cpu_utilization_percent: util,
            };

            return serde_json::to_string_pretty(&info)
                .map_err(|e| format!("Serialization error: {e}"));
        }
    }

    // Minimal fallback
    let fallback = CpuInfo {
        load_average: LoadAverage {
            one_minute: 0.0,
            five_minute: 0.0,
            fifteen_minute: 0.0,
        },
        cpu_count,
        cpu_utilization_percent: 0.0,
    };
    serde_json::to_string_pretty(&fallback).map_err(|e| format!("Serialization error: {e}"))
}

/// Retrieve top resource-consuming processes sorted by CPU or Memory.
pub async fn get_top_processes(
    limit: Option<usize>,
    sort_by: Option<&str>,
) -> Result<String, String> {
    let limit_num = limit.unwrap_or(10).clamp(1, 100);
    let sort_metric = sort_by.unwrap_or("cpu").to_lowercase();

    if sort_metric != "cpu" && sort_metric != "memory" && sort_metric != "mem" {
        return Err(format!(
            "Invalid sort_by metric '{sort_metric}': must be 'cpu' or 'memory'"
        ));
    }

    // 1. Try running `ps` on Linux/Unix
    let mut cmd = tokio::process::Command::new("ps");
    cmd.args(["-eo", "pid,comm,%cpu,%mem"]);
    if let Some(stdout) = crate::executor::execute_quick_process(cmd, 5).await {
        let mut processes = parse_ps_output(&stdout);

        if sort_metric.starts_with("mem") {
            processes.sort_by(|a, b| {
                b.memory_percent
                    .partial_cmp(&a.memory_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        } else {
            processes.sort_by(|a, b| {
                b.cpu_percent
                    .partial_cmp(&a.cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        processes.truncate(limit_num);
        return serde_json::to_string_pretty(&processes)
            .map_err(|e| format!("Serialization error: {e}"));
    }

    // 2. Windows fallback via PowerShell
    if cfg!(windows) {
        let ps_prop = if sort_metric.starts_with("mem") {
            "WorkingSet64"
        } else {
            "CPU"
        };
        let ps_cmd = format!(
            "Get-Process | Sort-Object {ps_prop} -Descending | Select-Object -First {limit_num} -Property Id, ProcessName, CPU, WorkingSet64 | ConvertTo-Json"
        );

        let mut ps = tokio::process::Command::new("powershell");
        ps.args(["-Command", &ps_cmd]);
        if let Some(stdout) = crate::executor::execute_quick_process(ps, 5).await
            && let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout)
        {
            let items = if val.is_array() {
                val.as_array().cloned().unwrap_or_default()
            } else if val.is_object() {
                vec![val]
            } else {
                Vec::new()
            };

            let mut procs = Vec::new();
            for item in items {
                let pid = item["Id"].as_u64().unwrap_or(0) as u32;
                let name = item["ProcessName"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();
                let cpu_raw = item["CPU"].as_f64().unwrap_or(0.0);
                let ws_bytes = item["WorkingSet64"].as_f64().unwrap_or(0.0);

                // Normalize CPU and memory for readability
                let cpu_pct = (cpu_raw.clamp(0.0, 1000.0) * 10.0).round() / 10.0;
                let mem_mb = ws_bytes / (1024.0 * 1024.0);
                let mem_pct = (mem_mb / 16384.0 * 100.0).clamp(0.0, 100.0);

                procs.push(ProcessInfo {
                    pid,
                    name,
                    cpu_percent: cpu_pct,
                    memory_percent: (mem_pct * 10.0).round() / 10.0,
                });
            }

            return serde_json::to_string_pretty(&procs)
                .map_err(|e| format!("Serialization error: {e}"));
        }
    }

    let empty: Vec<ProcessInfo> = Vec::new();
    serde_json::to_string_pretty(&empty).map_err(|e| format!("Serialization error: {e}"))
}

/// Collect network interface traffic statistics and active TCP connections.
pub async fn get_network_stats() -> Result<String, String> {
    let mut interfaces = Vec::new();
    let mut active_tcp_connections = 0;

    // 1. Linux /proc/net implementation
    if let Ok(dev_content) = tokio::fs::read_to_string("/proc/net/dev").await {
        interfaces = parse_proc_net_dev(&dev_content);

        if let Ok(tcp_content) = tokio::fs::read_to_string("/proc/net/tcp").await {
            active_tcp_connections += count_established_tcp_connections(&tcp_content);
        }
        if let Ok(tcp6_content) = tokio::fs::read_to_string("/proc/net/tcp6").await {
            active_tcp_connections += count_established_tcp_connections(&tcp6_content);
        }
    }

    // 2. Windows fallback if /proc/net is empty
    if interfaces.is_empty() && cfg!(windows) {
        let ps_cmd = "Get-NetAdapterStatistics | Select-Object Name, ReceivedBytes, SentBytes | ConvertTo-Json";
        let mut ps1 = tokio::process::Command::new("powershell");
        ps1.args(["-Command", ps_cmd]);
        if let Some(stdout) = crate::executor::execute_quick_process(ps1, 5).await
            && let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout)
        {
            let items = if val.is_array() {
                val.as_array().cloned().unwrap_or_default()
            } else if val.is_object() {
                vec![val]
            } else {
                Vec::new()
            };

            for item in items {
                let name = item["Name"].as_str().unwrap_or("eth").to_string();
                let rx = item["ReceivedBytes"].as_u64().unwrap_or(0);
                let tx = item["SentBytes"].as_u64().unwrap_or(0);

                interfaces.push(InterfaceStats {
                    interface: name,
                    rx_bytes: rx,
                    rx_packets: rx / 1400,
                    rx_errors: 0,
                    rx_dropped: 0,
                    tx_bytes: tx,
                    tx_packets: tx / 1400,
                    tx_errors: 0,
                    tx_dropped: 0,
                });
            }
        }

        // Active TCP connections count on Windows
        let tcp_cmd = "(Get-NetTCPConnection -State Established).Count";
        let mut ps2 = tokio::process::Command::new("powershell");
        ps2.args(["-Command", tcp_cmd]);
        if let Some(s) = crate::executor::execute_quick_process(ps2, 5).await
            && let Some(first) = s.lines().next()
            && let Ok(c) = first.trim().parse::<usize>()
        {
            active_tcp_connections = c;
        }
    }

    let listening_ports_count = crate::inspector::collect_listening_ports().await.len();

    let stats = NetworkStats {
        interfaces,
        active_tcp_connections,
        listening_ports_count,
    };

    serde_json::to_string_pretty(&stats).map_err(|e| format!("Serialization error: {e}"))
}

/// Tail systemd service logs via journalctl with optional time window and apply Smart Log Engine compression.
pub async fn tail_service_logs(
    service_name: &str,
    lines: Option<usize>,
    since: Option<&str>,
    until: Option<&str>,
) -> Result<String, String> {
    let default_sec = crate::config::SecurityConfig::default();
    tail_service_logs_with_config(service_name, lines, since, until, &default_sec).await
}

/// Tail systemd service logs via journalctl with optional time window and SecurityConfig verification.
pub async fn tail_service_logs_with_config(
    service_name: &str,
    lines: Option<usize>,
    since: Option<&str>,
    until: Option<&str>,
    security: &crate::config::SecurityConfig,
) -> Result<String, String> {
    let clean_service = service_name.trim();

    // 1. Enforce Guard safety validation on service name
    crate::guard::check_service_log_query_safety_with_config(clean_service, security)
        .map_err(|e| format!("Security Violation: {e}"))?;

    let line_count = lines.unwrap_or(50).clamp(1, 1000);

    // Validate structured arguments, time formats, and since <= until range
    let journal_args = build_journalctl_args_internal(clean_service, line_count, since, until)?;

    // 2. Check if journalctl binary is available on the system
    let journalctl_available = if cfg!(windows) {
        false
    } else {
        tokio::process::Command::new("which")
            .arg("journalctl")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    if !journalctl_available {
        return Ok(format!(
            "Logs for service '{clean_service}': (Host notice: journalctl is not active or available in current environment)"
        ));
    }

    // 3. Execute journalctl directly without shell wrapping
    let mut journal_cmd = tokio::process::Command::new("journalctl");
    journal_cmd.args(&journal_args);

    let limits = crate::executor::CommandLimits {
        timeout: std::time::Duration::from_secs(10),
        max_stdout_bytes: 1_048_576,
        max_stderr_bytes: 256 * 1024,
        termination_grace: std::time::Duration::from_millis(500),
    };

    let output_res = crate::executor::execute_process_bounded(journal_cmd, &limits).await;

    match output_res {
        Ok(outcome) => {
            let stdout = outcome.stdout_lossy();
            let stderr = outcome.stderr_lossy();
            let raw_text = if !stdout.trim().is_empty() {
                format!("{stdout}\n{stderr}")
            } else {
                stderr
            };

            // 4. Compress output through Smart Log Engine
            let compressed = crate::executor::compress_journal_logs(&raw_text, clean_service);
            Ok(compressed)
        }
        Err(err) => {
            warn!(service = %clean_service, error = %err, "Failed to spawn journalctl");
            Ok(format!(
                "Logs for service '{clean_service}': (Host notice: journalctl execution failed: {err})"
            ))
        }
    }
}

/// Builds and validates structured journalctl arguments with strict RFC 3339 time format and range checks.
pub fn build_journalctl_args(
    service_name: &str,
    lines: usize,
    since: Option<&str>,
    until: Option<&str>,
) -> Result<Vec<String>, String> {
    let clean_service = service_name.trim();
    crate::guard::check_service_log_query_safety(clean_service)
        .map_err(|e| format!("Security Violation: {e}"))?;

    let line_count = lines.clamp(1, 1000);
    build_journalctl_args_internal(clean_service, line_count, since, until)
}

fn build_journalctl_args_internal(
    clean_service: &str,
    line_count: usize,
    since: Option<&str>,
    until: Option<&str>,
) -> Result<Vec<String>, String> {
    let parsed_since = match since {
        Some(s) => {
            let s_trimmed = s.trim();
            if s_trimmed.is_empty() {
                return Err("Parameter 'since' cannot be empty when provided".to_string());
            }
            let dt = chrono::DateTime::parse_from_rfc3339(s_trimmed)
                .map_err(|e| format!("Invalid 'since' timestamp format (expected RFC 3339, e.g. '2026-10-14T00:00:00Z'): {e}"))?;
            Some((s_trimmed.to_string(), dt))
        }
        None => None,
    };

    let parsed_until = match until {
        Some(u) => {
            let u_trimmed = u.trim();
            if u_trimmed.is_empty() {
                return Err("Parameter 'until' cannot be empty when provided".to_string());
            }
            let dt = chrono::DateTime::parse_from_rfc3339(u_trimmed)
                .map_err(|e| format!("Invalid 'until' timestamp format (expected RFC 3339, e.g. '2026-10-14T00:00:00Z'): {e}"))?;
            Some((u_trimmed.to_string(), dt))
        }
        None => None,
    };

    if let (Some((_, s_dt)), Some((_, u_dt))) = (&parsed_since, &parsed_until)
        && s_dt > u_dt
    {
        return Err(
            "Invalid time range: 'since' must be earlier than or equal to 'until'".to_string(),
        );
    }

    let mut args = vec![
        "-u".to_string(),
        clean_service.to_string(),
        "-n".to_string(),
        line_count.to_string(),
        "--no-pager".to_string(),
    ];

    if let Some((s_val, _)) = parsed_since {
        args.push("--since".to_string());
        args.push(s_val);
    }

    if let Some((u_val, _)) = parsed_until {
        args.push("--until".to_string());
        args.push(u_val);
    }

    Ok(args)
}

// -----------------------------------------------------------------------------
// McpTool Implementations
// -----------------------------------------------------------------------------

use crate::mcp::protocol::CallToolResult;
use crate::tools::registry::{McpTool, ToolContext, ToolRegistry};
use async_trait::async_trait;

pub struct GetDiskUsageTool;

#[async_trait]
impl McpTool for GetDiskUsageTool {
    fn name(&self) -> &str {
        "get_disk_usage"
    }

    fn description(&self) -> &str {
        "Inspects mounted filesystems and available disk space in human-readable format and percentages."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Optional directory or mount path to inspect disk usage for."
                }
            },
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let path = args.get("path").and_then(|p| p.as_str());
        match get_disk_usage_with_config(path, &ctx.config.security).await {
            Ok(res) => Ok(CallToolResult::text(res)),
            Err(e) => Ok(CallToolResult::error(e)),
        }
    }
}

pub struct GetCpuInfoTool;

#[async_trait]
impl McpTool for GetCpuInfoTool {
    fn name(&self) -> &str {
        "get_cpu_info"
    }

    fn description(&self) -> &str {
        "Returns current CPU load average (1, 5, 15 minutes), core count, and real-time CPU utilization percentage."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        _args: serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        match get_cpu_info().await {
            Ok(res) => Ok(CallToolResult::text(res)),
            Err(e) => Ok(CallToolResult::error(e)),
        }
    }
}

pub struct GetTopProcessesTool;

#[async_trait]
impl McpTool for GetTopProcessesTool {
    fn name(&self) -> &str {
        "get_top_processes"
    }

    fn description(&self) -> &str {
        "Returns top resource-consuming processes sorted by CPU or memory usage with PID, name, and percentages."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "description": "Maximum number of processes to return (default 10)."
                },
                "sort_by": {
                    "type": "string",
                    "enum": ["cpu", "memory"],
                    "description": "Resource metric to sort by ('cpu' or 'memory', default 'cpu')."
                }
            },
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let limit = args
            .get("limit")
            .and_then(|l| l.as_u64())
            .map(|l| l as usize);
        let sort_by = args.get("sort_by").and_then(|s| s.as_str());

        match get_top_processes(limit, sort_by).await {
            Ok(res) => Ok(CallToolResult::text(res)),
            Err(e) => Ok(CallToolResult::error(e)),
        }
    }
}

pub struct GetNetworkStatsTool;

#[async_trait]
impl McpTool for GetNetworkStatsTool {
    fn name(&self) -> &str {
        "get_network_stats"
    }

    fn description(&self) -> &str {
        "Returns network interface statistics (RX/TX bytes, packets, errors, drops) and active TCP connections count."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        _args: serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        match get_network_stats().await {
            Ok(res) => Ok(CallToolResult::text(res)),
            Err(e) => Ok(CallToolResult::error(e)),
        }
    }
}

pub struct TailServiceLogsTool;

#[async_trait]
impl McpTool for TailServiceLogsTool {
    fn name(&self) -> &str {
        "tail_service_logs"
    }

    fn description(&self) -> &str {
        "Reads system service logs via journalctl with optional time filtering (since, until in RFC 3339) and compresses them with Smart Log Engine."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "service_name": {
                    "type": "string",
                    "description": "Name of the system service (e.g. 'nginx', 'sshd', 'vibe-daemon')."
                },
                "lines": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "description": "Number of recent log lines to retrieve (default 50)."
                },
                "since": {
                    "type": "string",
                    "description": "Optional start timestamp in RFC 3339 format (e.g. '2026-10-14T00:00:00Z')."
                },
                "until": {
                    "type": "string",
                    "description": "Optional end timestamp in RFC 3339 format (e.g. '2026-10-14T12:00:00Z')."
                }
            },
            "required": ["service_name"],
            "additionalProperties": false
        })
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<CallToolResult, String> {
        let service_arg = args.get("service_name").and_then(|s| s.as_str());
        let lines_arg = args
            .get("lines")
            .and_then(|l| l.as_u64())
            .map(|l| l as usize);
        let since_arg = args.get("since").and_then(|s| s.as_str());
        let until_arg = args.get("until").and_then(|u| u.as_str());

        match service_arg {
            Some(service) => {
                match tail_service_logs_with_config(
                    service,
                    lines_arg,
                    since_arg,
                    until_arg,
                    &ctx.config.security,
                )
                .await
                {
                    Ok(output) => Ok(CallToolResult::text(output)),
                    Err(e) => Ok(CallToolResult::error(e)),
                }
            }
            None => Ok(CallToolResult::error(
                "Missing required parameter: 'service_name' must be a string",
            )),
        }
    }
}

/// Registers the 5 monitoring tools into the given registry.
pub fn register_monitoring_tools(registry: &mut ToolRegistry) {
    registry.register_tool(GetDiskUsageTool);
    registry.register_tool(GetCpuInfoTool);
    registry.register_tool(GetTopProcessesTool);
    registry.register_tool(GetNetworkStatsTool);
    registry.register_tool(TailServiceLogsTool);
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_df_output_standard() {
        let df_output = "Filesystem      Size  Used Avail Use% Mounted on\n\
                         udev            3.9G     0  3.9G   0% /dev\n\
                         tmpfs           793M  1.4M  792M   1% /run\n\
                         /dev/sda1        49G   22G   25G  47% /\n\
                         tmpfs           3.9G     0  3.9G   0% /dev/shm\n\
                         /dev/sdb1       500G  300G  180G  63% /data storage";

        let parsed = parse_df_output(df_output);
        assert_eq!(parsed.len(), 5);

        assert_eq!(parsed[2].filesystem, "/dev/sda1");
        assert_eq!(parsed[2].total, "49G");
        assert_eq!(parsed[2].used, "22G");
        assert_eq!(parsed[2].available, "25G");
        assert_eq!(parsed[2].use_percent, "47%");
        assert_eq!(parsed[2].mounted_on, "/");

        assert_eq!(parsed[4].filesystem, "/dev/sdb1");
        assert_eq!(parsed[4].mounted_on, "/data storage");
    }

    #[test]
    fn test_parse_df_output_split_lines() {
        let df_output = "Filesystem      Size  Used Avail Use% Mounted on\n\
                         /dev/mapper/ubuntu--vg-ubuntu--lv\n\
                                          98G   45G   49G  48% /\n\
                         /dev/sda2       1.9G  250M  1.5G  15% /boot";

        let parsed = parse_df_output(df_output);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].filesystem, "/dev/mapper/ubuntu--vg-ubuntu--lv");
        assert_eq!(parsed[0].total, "98G");
        assert_eq!(parsed[0].mounted_on, "/");
        assert_eq!(parsed[1].filesystem, "/dev/sda2");
    }

    #[test]
    fn test_parse_proc_loadavg() {
        let content = "0.25 0.18 0.12 2/485 12845\n";
        let load = parse_proc_loadavg(content).expect("Must parse loadavg");
        assert_eq!(load.one_minute, 0.25);
        assert_eq!(load.five_minute, 0.18);
        assert_eq!(load.fifteen_minute, 0.12);
    }

    #[test]
    fn test_parse_proc_stat_cpu_line_and_utilization() {
        // cpu  user nice system idle iowait irq softirq steal guest guest_nice
        let line1 = "cpu  2000 0 1000 7000 0 0 0 0 0 0";
        let sample1 = parse_proc_stat_cpu_line(line1).expect("Must parse cpu line 1");
        assert_eq!(sample1.0, 7000); // idle
        assert_eq!(sample1.1, 10000); // total

        // 100 total ticks later: 50 busy, 50 idle -> 50% utilization
        let line2 = "cpu  2025 0 1025 7050 0 0 0 0 0 0";
        let sample2 = parse_proc_stat_cpu_line(line2).expect("Must parse cpu line 2");
        assert_eq!(sample2.0, 7050);
        assert_eq!(sample2.1, 10100);

        let util = calculate_cpu_utilization(sample1, sample2);
        assert_eq!(util, 50.0);
    }

    #[test]
    fn test_parse_ps_output() {
        let ps_output = "  PID COMMAND         %CPU %MEM\n\
                            1 systemd          0.0  0.1\n\
                          500 /usr/sbin/nginx  1.5  2.4\n\
                         1200 cargo test       85.4  12.0\n\
                         1250 multi word proc  10.2  4.5";

        let procs = parse_ps_output(ps_output);
        assert_eq!(procs.len(), 4);

        assert_eq!(procs[0].pid, 1);
        assert_eq!(procs[0].name, "systemd");
        assert_eq!(procs[0].cpu_percent, 0.0);
        assert_eq!(procs[0].memory_percent, 0.1);

        assert_eq!(procs[1].pid, 500);
        assert_eq!(procs[1].name, "/usr/sbin/nginx");
        assert_eq!(procs[1].cpu_percent, 1.5);
        assert_eq!(procs[1].memory_percent, 2.4);

        assert_eq!(procs[3].pid, 1250);
        assert_eq!(procs[3].name, "multi word proc");
        assert_eq!(procs[3].cpu_percent, 10.2);
    }

    #[test]
    fn test_parse_proc_net_dev() {
        let net_dev = "Inter-|   Receive                                                |  Transmit\n\
                        face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                           lo: 1000000   10000    0    0    0     0          0         0  1000000   10000    0    0    0     0       0          0\n\
                         eth0: 50000000  45000    5    1    0     0          0         0 20000000   32000    2    0    0     0       0          0";

        let stats = parse_proc_net_dev(net_dev);
        assert_eq!(stats.len(), 2);

        assert_eq!(stats[0].interface, "lo");
        assert_eq!(stats[0].rx_bytes, 1000000);
        assert_eq!(stats[0].tx_bytes, 1000000);

        assert_eq!(stats[1].interface, "eth0");
        assert_eq!(stats[1].rx_bytes, 50000000);
        assert_eq!(stats[1].rx_errors, 5);
        assert_eq!(stats[1].rx_dropped, 1);
        assert_eq!(stats[1].tx_bytes, 20000000);
        assert_eq!(stats[1].tx_errors, 2);
    }

    #[test]
    fn test_count_established_tcp_connections() {
        let tcp_content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                            0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n\
                            1: 0100007F:1F90 0100007F:ABCD 01 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 100 0 0 10 0\n\
                            2: 0100007F:1F90 0100007F:DCBA 01 00000000:00000000 00:00000000 00000000  1000        0 23457 1 0000000000000000 100 0 0 10 0\n\
                            3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 34567 1 0000000000000000 100 0 0 10 0";

        let established = count_established_tcp_connections(tcp_content);
        assert_eq!(established, 2);
    }

    #[tokio::test]
    async fn test_get_disk_usage_live() {
        let res = get_disk_usage(None).await;
        assert!(res.is_ok());
        let json_text = res.unwrap();
        let disks: Vec<DiskUsage> = serde_json::from_str(&json_text).expect("Must be valid JSON");
        assert!(!disks.is_empty());
    }

    #[tokio::test]
    async fn test_get_cpu_info_live() {
        let res = get_cpu_info().await;
        assert!(res.is_ok());
        let json_text = res.unwrap();
        let info: CpuInfo = serde_json::from_str(&json_text).expect("Must be valid JSON");
        assert!(info.cpu_count >= 1);
    }

    #[tokio::test]
    async fn test_get_top_processes_live() {
        let res = get_top_processes(Some(5), Some("cpu")).await;
        assert!(res.is_ok());
        let json_text = res.unwrap();
        let procs: Vec<ProcessInfo> = serde_json::from_str(&json_text).expect("Must be valid JSON");
        assert!(procs.len() <= 5);
    }

    #[tokio::test]
    async fn test_get_network_stats_live() {
        let res = get_network_stats().await;
        assert!(res.is_ok());
        let json_text = res.unwrap();
        let stats: NetworkStats = serde_json::from_str(&json_text).expect("Must be valid JSON");
        // Check struct serializability and valid numeric fields
        assert!(stats.listening_ports_count <= 65535);
    }

    #[tokio::test]
    async fn test_tail_service_logs_guard_blocked() {
        let res = tail_service_logs("nginx; rm -rf /", Some(10), None, None).await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.contains("Security Violation"));
    }

    #[tokio::test]
    async fn test_tail_service_logs_safe() {
        let res = tail_service_logs("nginx", Some(10), None, None).await;
        assert!(res.is_ok());
        let output = res.unwrap();
        assert!(output.contains("nginx"));
    }

    #[test]
    fn test_build_journalctl_args_structured_and_time_filters() {
        let args = build_journalctl_args(
            "nginx",
            100,
            Some("2026-10-14T00:00:00Z"),
            Some("2026-10-14T12:00:00Z"),
        )
        .expect("Valid args expected");

        assert_eq!(
            args,
            vec![
                "-u",
                "nginx",
                "-n",
                "100",
                "--no-pager",
                "--since",
                "2026-10-14T00:00:00Z",
                "--until",
                "2026-10-14T12:00:00Z"
            ]
        );
    }

    #[test]
    fn test_build_journalctl_args_invalid_rfc3339_since() {
        let err =
            build_journalctl_args("nginx", 50, Some("invalid-date-format"), None).unwrap_err();
        assert!(err.contains("Invalid 'since' timestamp format"));
    }

    #[test]
    fn test_build_journalctl_args_invalid_rfc3339_until() {
        let err =
            build_journalctl_args("nginx", 50, None, Some("2026/10/14 12:00:00")).unwrap_err();
        assert!(err.contains("Invalid 'until' timestamp format"));
    }

    #[test]
    fn test_build_journalctl_args_since_greater_than_until() {
        let err = build_journalctl_args(
            "nginx",
            50,
            Some("2026-10-14T15:00:00Z"),
            Some("2026-10-14T10:00:00Z"),
        )
        .unwrap_err();
        assert!(err.contains("since' must be earlier than or equal to 'until"));
    }

    #[tokio::test]
    async fn test_tail_service_logs_with_valid_time_window() {
        let res = tail_service_logs(
            "sshd",
            Some(25),
            Some("2026-10-14T00:00:00Z"),
            Some("2026-10-14T06:00:00Z"),
        )
        .await;
        assert!(res.is_ok());
        let output = res.unwrap();
        assert!(output.contains("sshd"));
    }

    #[tokio::test]
    async fn test_tail_service_logs_rejects_inverted_time_window() {
        let res = tail_service_logs(
            "sshd",
            Some(25),
            Some("2026-10-14T18:00:00Z"),
            Some("2026-10-14T06:00:00Z"),
        )
        .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Invalid time range"));
    }
}
