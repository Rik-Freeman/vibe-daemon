//! Security Guard and Firewall subsystem.
//! Performs proactive inspection of commands, blocks destructive patterns,
//! protects critical ports/services (e.g. SSH port 22 and vibe-daemon itself),
//! and provides intelligent port conflict arbitration.

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Security Violations & Types
// -----------------------------------------------------------------------------

/// Security violation categories for blocked commands and operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityViolation {
    DestructiveCommand(String),
    SelfTermination(String),
    CriticalPortOrServiceTampering(String),
    ForkBomb(String),
    ProtectedPathTampering(String),
}

impl std::fmt::Display for SecurityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DestructiveCommand(reason) => write!(f, "Destructive command blocked: {reason}"),
            Self::SelfTermination(reason) => {
                write!(f, "Self-termination attempt blocked: {reason}")
            }
            Self::CriticalPortOrServiceTampering(reason) => {
                write!(
                    f,
                    "Tampering with critical port or service blocked: {reason}"
                )
            }
            Self::ForkBomb(reason) => write!(f, "Fork bomb pattern blocked: {reason}"),
            Self::ProtectedPathTampering(reason) => {
                write!(f, "Tampering with protected path blocked: {reason}")
            }
        }
    }
}

impl std::error::Error for SecurityViolation {}

/// Structured conflict error returned when a requested network port is in use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortConflict {
    pub requested_port: u16,
    pub occupied_by_process: Option<String>,
    pub occupied_by_pid: Option<u32>,
    pub message: String,
    pub suggested_alternative_port: u16,
}

impl std::fmt::Display for PortConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PortConflict {}

// -----------------------------------------------------------------------------
// Command Pattern Guard & Blacklist
// -----------------------------------------------------------------------------

/// Verify that a command string does not contain dangerous or destructive patterns using default configuration.
pub fn check_command_safety(command: &str) -> Result<(), SecurityViolation> {
    let default_sec = crate::config::SecurityConfig::default();
    check_command_safety_with_config(command, &default_sec)
}

/// Verify that a command string does not contain dangerous or destructive patterns using specified SecurityConfig.
pub fn check_command_safety_with_config(
    command: &str,
    security: &crate::config::SecurityConfig,
) -> Result<(), SecurityViolation> {
    let raw = command.trim();
    if raw.is_empty() {
        return Ok(());
    }

    let lower = raw.to_lowercase();

    // 1. Fork bomb checks
    if lower.contains(":(){ :|:& };:")
        || lower.contains(":(){:|:&};:")
        || lower.contains("(){ :|:& };")
        || lower.contains("fork bomb")
    {
        return Err(SecurityViolation::ForkBomb(
            "Fork bomb signature detected".to_string(),
        ));
    }

    // 2. Direct raw storage writes
    if lower.contains("> /dev/sd")
        || lower.contains("> /dev/nvme")
        || lower.contains("> /dev/vd")
        || lower.contains("> /dev/hd")
    {
        return Err(SecurityViolation::DestructiveCommand(
            "Direct raw storage block device write detected".to_string(),
        ));
    }

    if lower.contains("dd if=") && lower.contains("of=/dev/") && !lower.contains("of=/dev/null") {
        return Err(SecurityViolation::DestructiveCommand(
            "Low-level block device write with dd detected".to_string(),
        ));
    }

    // 3. Inspect compound commands (split by ;, &&, ||, |, &, newline)
    let separators = [";", "&&", "||", "|", "&", "\n"];
    let mut sub_commands = vec![lower.as_str()];

    for sep in separators {
        let mut next_split = Vec::new();
        for segment in sub_commands {
            for part in segment.split(sep) {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    next_split.push(trimmed);
                }
            }
        }
        sub_commands = next_split;
    }

    for sub in sub_commands {
        check_single_subcommand(sub, security)?;
    }

    Ok(())
}

fn check_single_subcommand(
    sub: &str,
    security: &crate::config::SecurityConfig,
) -> Result<(), SecurityViolation> {
    // Recursively strip common privilege and wrapper prefixes (e.g. sudo sudo, nohup sudo, doas)
    let mut normalized = sub.trim();
    let prefixes = ["sudo ", "doas ", "nohup ", "eval ", "exec "];
    loop {
        let mut changed = false;
        for prefix in prefixes {
            if let Some(stripped) = normalized.strip_prefix(prefix) {
                normalized = stripped.trim();
                changed = true;
                break;
            }
        }
        if !changed {
            break;
        }
    }

    // 1. Protection of vibe-daemon (Self-preservation)
    if normalized.contains("vibe-daemon") {
        let is_stopping = normalized.contains("stop")
            || normalized.contains("disable")
            || normalized.contains("mask")
            || normalized.contains("kill")
            || normalized.contains("restart")
            || normalized.contains("killall")
            || normalized.contains("pkill");

        if is_stopping {
            return Err(SecurityViolation::SelfTermination(
                "Attempt to stop, kill or disable vibe-daemon service".to_string(),
            ));
        }
    }

    // 2. Critical Ports and SSH/Protected Services Protection
    if is_ssh_or_port22_tampering(normalized, security) {
        return Err(SecurityViolation::CriticalPortOrServiceTampering(
            "Attempt to stop, block or tamper with critical SSH service or port 22".to_string(),
        ));
    }

    // 3. Destructive root/system removal
    if is_destructive_rm(normalized) {
        return Err(SecurityViolation::DestructiveCommand(
            "Recursive deletion of root or critical filesystem hierarchy".to_string(),
        ));
    }

    // 4. Low level filesystem formatting or wiping
    if normalized.starts_with("mkfs")
        || normalized.contains(" mkfs")
        || normalized.starts_with("wipefs")
        || normalized.contains(" wipefs")
        || normalized.starts_with("format c:")
    {
        return Err(SecurityViolation::DestructiveCommand(
            "Filesystem formatting or partition wipe command detected".to_string(),
        ));
    }

    // 5. System shutdown or reboot
    if normalized.starts_with("shutdown")
        || normalized == "reboot"
        || normalized.starts_with("reboot ")
        || normalized == "poweroff"
        || normalized.starts_with("poweroff ")
        || normalized == "halt"
        || normalized.starts_with("halt ")
        || normalized == "init 0"
        || normalized == "init 6"
    {
        return Err(SecurityViolation::DestructiveCommand(
            "Host shutdown, reboot, or runlevel halt command detected".to_string(),
        ));
    }

    // 6. Destructive Docker operations
    if is_destructive_docker(normalized) {
        return Err(SecurityViolation::DestructiveCommand(
            "Destructive Docker command (forced removal of running containers or volume pruning) blocked"
                .to_string(),
        ));
    }

    // 7. Destructive Certbot operations
    if is_destructive_certbot(normalized) {
        return Err(SecurityViolation::DestructiveCommand(
            "Destructive certbot command (certificate revocation, deletion, or unregistering) blocked"
                .to_string(),
        ));
    }

    Ok(())
}

fn is_destructive_certbot(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    if !lower.contains("certbot") {
        return false;
    }
    lower.contains("certbot revoke")
        || lower.contains("certbot delete")
        || lower.contains("certbot unregister")
}

fn is_destructive_docker(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    if !lower.contains("docker") && !lower.contains("podman") {
        return false;
    }

    // Forced container removal (docker rm -f, docker rm --force)
    (lower.contains(" rm ") && (lower.contains(" -f") || lower.contains(" --force")))
        // Volume prune or forced volume removal
        || lower.contains("volume prune")
        || lower.contains("volume rm")
        // Destructive system prune
        || (lower.contains("system prune")
            && (lower.contains(" -a")
                || lower.contains(" --all")
                || lower.contains(" --volumes")
                || lower.contains(" -f")
                || lower.contains(" --force")))
        // Container prune
        || lower.contains("container prune")
}

fn is_ssh_or_port22_tampering(cmd: &str, security: &crate::config::SecurityConfig) -> bool {
    // Stopping or disabling protected services
    for svc in &security.protected_services {
        let clean = svc.trim().to_lowercase();
        let name = clean.strip_suffix(".service").unwrap_or(&clean);
        if cmd.contains(&format!("systemctl stop {name}"))
            || cmd.contains(&format!("systemctl disable {name}"))
            || cmd.contains(&format!("service {name} stop"))
            || cmd.contains(&format!("pkill {name}"))
            || cmd.contains(&format!("killall {name}"))
        {
            return true;
        }
    }

    // Blocking protected ports via UFW
    for port in &security.protected_ports {
        let p_str = port.to_string();
        if cmd.contains(&format!("ufw deny {p_str}"))
            || cmd.contains(&format!("ufw delete allow {p_str}"))
        {
            return true;
        }

        let is_firewall = cmd.contains("iptables") || cmd.contains("nft");
        let has_port = cmd.contains(&p_str);
        let is_drop = cmd.contains("drop") || cmd.contains("reject");
        if is_firewall && has_port && is_drop {
            return true;
        }
    }

    // UFW blocking SSH / 22 alias
    if security.protected_ports.contains(&22) {
        if cmd.contains("ufw deny ssh") || cmd.contains("ufw delete allow ssh") {
            return true;
        }
        let is_firewall = cmd.contains("iptables") || cmd.contains("nft");
        let has_ssh = cmd.contains("ssh");
        let is_drop = cmd.contains("drop") || cmd.contains("reject");
        if is_firewall && has_ssh && is_drop {
            return true;
        }
    }

    // fuser killing port 22
    if cmd.contains("fuser -k") && cmd.contains("22") {
        return true;
    }

    false
}

fn is_destructive_rm(cmd: &str) -> bool {
    if !cmd.starts_with("rm") && !cmd.contains(" rm") {
        return false;
    }

    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let has_recursive = tokens.iter().any(|&t| {
        t == "-r"
            || t == "-rf"
            || t == "-fr"
            || t == "-rfi"
            || t == "-rif"
            || t == "-R"
            || t == "--recursive"
    });

    if !has_recursive {
        return false;
    }

    let targets = [
        "/",
        "/*",
        "~",
        "/etc",
        "/boot",
        "/sys",
        "/proc",
        "/dev",
        "/usr",
        "/var",
        "--no-preserve-root",
    ];

    tokens.iter().any(|&token| targets.contains(&token))
}

// -----------------------------------------------------------------------------
// Smart Port Resolver (Port Arbitration)
// -----------------------------------------------------------------------------

/// Find a suitable free alternative port if the requested port is busy.
pub fn find_alternative_port(
    requested_port: u16,
    active_ports: &[crate::inspector::ListeningPort],
) -> u16 {
    // If standard web ports (80, 443), prefer standard non-privileged alternatives
    let candidates: Vec<u16> = match requested_port {
        80 => vec![8080, 8000, 8001, 8081, 8888],
        443 => vec![8443, 9443, 8444],
        other => {
            let mut list = Vec::new();
            // Try +1, +2, +3... up to +20
            for offset in 1..=20 {
                if let Some(next) = other.checked_add(offset) {
                    list.push(next);
                }
            }
            // Also append standard alternative development range 8000..=8010
            for p in 8000..=8010 {
                if !list.contains(&p) {
                    list.push(p);
                }
            }
            list
        }
    };

    for candidate in candidates {
        if !active_ports.iter().any(|p| p.port == candidate) {
            return candidate;
        }
    }

    // Default fallback
    if requested_port < 65534 {
        requested_port + 1
    } else {
        8080
    }
}

/// Check if a specific port is already in use by an active listener.
/// If occupied, returns a structured `PortConflict` with holding process info and alternative.
pub fn check_port_availability(
    requested_port: u16,
    active_ports: &[crate::inspector::ListeningPort],
) -> Result<(), PortConflict> {
    if let Some(conflict) = active_ports.iter().find(|p| p.port == requested_port) {
        let occupied_proc = conflict.process_name.clone();
        let occupied_pid = conflict.pid;
        let proc_desc = match (&occupied_proc, occupied_pid) {
            (Some(name), Some(pid)) => format!("process '{name}' (PID: {pid})"),
            (Some(name), None) => format!("process '{name}'"),
            (None, Some(pid)) => format!("PID {pid}"),
            (None, None) => "an active process".to_string(),
        };

        let alternative = find_alternative_port(requested_port, active_ports);

        return Err(PortConflict {
            requested_port,
            occupied_by_process: occupied_proc,
            occupied_by_pid: occupied_pid,
            message: format!(
                "Port {requested_port} is already in use by {proc_desc}. Recommended alternative: port {alternative}"
            ),
            suggested_alternative_port: alternative,
        });
    }

    Ok(())
}

/// Inspect command string and extract any specified network port binding argument.
pub fn extract_port_from_command(command: &str) -> Option<u16> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (i, &token) in tokens.iter().enumerate() {
        // e.g. --port 80 or -p 80
        if (token == "--port" || token == "-p") && i + 1 < tokens.len() {
            let next = tokens[i + 1];
            let port_part = next.split(':').next().unwrap_or(next);
            if let Ok(port) = port_part.parse::<u16>() {
                return Some(port);
            }
        }
        // e.g. --port=80
        if let Some(rest) = token.strip_prefix("--port=") {
            let port_part = rest.split(':').next().unwrap_or(rest);
            if let Ok(port) = port_part.parse::<u16>() {
                return Some(port);
            }
        }
        // e.g. -p80 or -p8080:80
        if let Some(rest) = token.strip_prefix("-p")
            && !rest.is_empty()
            && rest.chars().all(|c| c.is_ascii_digit() || c == ':')
        {
            let port_part = rest.split(':').next().unwrap_or(rest);
            if let Ok(port) = port_part.parse::<u16>() {
                return Some(port);
            }
        }
    }
    None
}

// -----------------------------------------------------------------------------
// Dedicated Firewall & Service Management Rules
// -----------------------------------------------------------------------------

/// Check if a port is critical to remote host survival using specified SecurityConfig.
pub fn is_critical_port_with_config(port: u16, security: &crate::config::SecurityConfig) -> bool {
    security.protected_ports.contains(&port)
}

/// Check if a port is critical to remote host survival using default SecurityConfig.
pub fn is_critical_port(port: u16) -> bool {
    let default_sec = crate::config::SecurityConfig::default();
    is_critical_port_with_config(port, &default_sec)
}

/// Verify that a port management operation does not violate security policy using specified SecurityConfig.
pub fn check_port_management_safety_with_config(
    action: &str,
    port: u16,
    security: &crate::config::SecurityConfig,
) -> Result<(), SecurityViolation> {
    let lower_action = action.to_lowercase();
    if (lower_action == "close" || lower_action == "deny" || lower_action == "delete")
        && is_critical_port_with_config(port, security)
    {
        let msg = if port == 22 {
            "Closing critical SSH port (22) is strictly prohibited".to_string()
        } else {
            format!("Closing protected port ({port}) is strictly prohibited")
        };
        return Err(SecurityViolation::CriticalPortOrServiceTampering(msg));
    }
    Ok(())
}

/// Verify that a port management operation does not violate security policy using default SecurityConfig.
pub fn check_port_management_safety(action: &str, port: u16) -> Result<(), SecurityViolation> {
    let default_sec = crate::config::SecurityConfig::default();
    check_port_management_safety_with_config(action, port, &default_sec)
}

/// Check if a service name belongs to the protected system infrastructure blacklist using specified SecurityConfig.
pub fn is_protected_service_with_config(
    service_name: &str,
    security: &crate::config::SecurityConfig,
) -> bool {
    let clean = service_name.trim().to_lowercase();
    let name = clean.strip_suffix(".service").unwrap_or(&clean);

    security.protected_services.iter().any(|s| {
        let s_clean = s.trim().to_lowercase();
        let s_name = s_clean.strip_suffix(".service").unwrap_or(&s_clean);
        s_name == name
    })
}

/// Check if a service name belongs to the protected system infrastructure blacklist using default SecurityConfig.
pub fn is_protected_service(service_name: &str) -> bool {
    let default_sec = crate::config::SecurityConfig::default();
    is_protected_service_with_config(service_name, &default_sec)
}

/// Verify that a service management operation does not violate security policy using specified SecurityConfig.
pub fn check_service_management_safety_with_config(
    service_name: &str,
    action: &str,
    security: &crate::config::SecurityConfig,
) -> Result<(), SecurityViolation> {
    let lower_action = action.to_lowercase();

    // Inspection ("status") is always safe and permitted for any service
    if lower_action == "status" {
        return Ok(());
    }

    let clean = service_name.trim().to_lowercase();
    let name = clean.strip_suffix(".service").unwrap_or(&clean);

    if is_protected_service_with_config(name, security) {
        if name == "vibe-daemon" {
            return Err(SecurityViolation::SelfTermination(
                "Managing critical service 'vibe-daemon' with restart/reload/stop is strictly prohibited"
                    .to_string(),
            ));
        }

        return Err(SecurityViolation::CriticalPortOrServiceTampering(format!(
            "Managing critical service '{service_name}' with action '{action}' is strictly prohibited"
        )));
    }

    Ok(())
}

/// Verify that a service management operation does not violate security policy using default SecurityConfig.
pub fn check_service_management_safety(
    service_name: &str,
    action: &str,
) -> Result<(), SecurityViolation> {
    let default_sec = crate::config::SecurityConfig::default();
    check_service_management_safety_with_config(service_name, action, &default_sec)
}

/// Verify that a service log query does not violate security policies or contain shell injection.
pub fn check_service_log_query_safety_with_config(
    service_name: &str,
    security: &crate::config::SecurityConfig,
) -> Result<(), SecurityViolation> {
    let trimmed = service_name.trim();
    if trimmed.is_empty() {
        return Err(SecurityViolation::DestructiveCommand(
            "Service name cannot be empty".to_string(),
        ));
    }

    // Must be a valid service identifier: letters, digits, underscore, dot, hyphen, @, colon
    if !trimmed.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '@' || c == ':'
    }) {
        return Err(SecurityViolation::DestructiveCommand(format!(
            "Invalid characters in service name '{trimmed}': service identifier must only contain alphanumeric, '.', '-', '_', '@', or ':'"
        )));
    }

    // Check command safety with security config
    check_command_safety_with_config(&format!("journalctl -u {trimmed}"), security)?;

    Ok(())
}

/// Verify that a service log query does not violate security policies using default SecurityConfig.
pub fn check_service_log_query_safety(service_name: &str) -> Result<(), SecurityViolation> {
    let default_sec = crate::config::SecurityConfig::default();
    check_service_log_query_safety_with_config(service_name, &default_sec)
}

/// Verify that a container identifier (name or ID) does not violate security policies or contain shell injection.
pub fn check_container_identifier_safety(name_or_id: &str) -> Result<(), SecurityViolation> {
    let trimmed = name_or_id.trim();
    if trimmed.is_empty() {
        return Err(SecurityViolation::DestructiveCommand(
            "Container identifier cannot be empty".to_string(),
        ));
    }

    // Must be a valid container identifier: alphanumeric, underscore, dot, hyphen, or slash
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/')
    {
        return Err(SecurityViolation::DestructiveCommand(format!(
            "Invalid characters in container identifier '{trimmed}': container identifier must only contain alphanumeric characters, '.', '-', '_', or '/'"
        )));
    }

    Ok(())
}

fn is_binary_available(binary: &str) -> bool {
    if cfg!(windows) {
        return false;
    }
    let standard_paths = [
        format!("/usr/sbin/{binary}"),
        format!("/usr/bin/{binary}"),
        format!("/sbin/{binary}"),
        format!("/bin/{binary}"),
    ];
    if standard_paths
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    {
        return true;
    }
    std::process::Command::new("which")
        .arg(binary)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Safely manage firewall rules for a given port using specified SecurityConfig.
pub async fn manage_firewall_port_with_config(
    action: &str,
    port: u16,
    protocol: Option<&str>,
    security: &crate::config::SecurityConfig,
) -> Result<String, SecurityViolation> {
    let action_lower = action.to_lowercase();
    check_port_management_safety_with_config(&action_lower, port, security)?;

    let proto = protocol.unwrap_or("tcp").to_lowercase();
    if proto != "tcp" && proto != "udp" {
        return Err(SecurityViolation::DestructiveCommand(format!(
            "Invalid protocol '{proto}', must be 'tcp' or 'udp'"
        )));
    }

    // Inspect active port status
    let active_ports = crate::inspector::collect_listening_ports().await;
    let listener_info = if let Some(p) = active_ports.iter().find(|p| p.port == port) {
        let proc = p.process_name.as_deref().unwrap_or("active process");
        let pid_str = p.pid.map_or("".to_string(), |pid| format!(" (PID {pid})"));
        format!(" [Notice: port {port} is currently bound by {proc}{pid_str}]")
    } else {
        "".to_string()
    };

    if !is_binary_available("ufw") {
        return Ok(format!(
            "Firewall rule '{action_lower}' for port {port}/{proto} processed.{listener_info} (Host notice: ufw binary is not active in current environment)"
        ));
    }

    let ufw_action = match action_lower.as_str() {
        "open" | "allow" => "allow",
        "close" | "deny" => "deny",
        other => {
            return Err(SecurityViolation::DestructiveCommand(format!(
                "Invalid port action '{other}', must be 'open' or 'close'"
            )));
        }
    };

    let mut ufw_proc = tokio::process::Command::new("ufw");
    let target_port_proto = format!("{port}/{proto}");
    ufw_proc.args([ufw_action, &target_port_proto]);

    let res = crate::executor::execute_process_with_smart_logs(
        ufw_proc,
        std::time::Duration::from_secs(15),
    )
    .await;

    match res {
        Ok(output) => Ok(format!(
            "Firewall updated successfully: {output}{listener_info}"
        )),
        Err(err) => {
            if err.contains("not recognized")
                || err.contains("not found")
                || err.contains("failed to spawn")
            {
                Ok(format!(
                    "Firewall rule '{action_lower}' for port {port}/{proto} processed.{listener_info} (Host notice: ufw binary is not active in current environment)"
                ))
            } else {
                Err(SecurityViolation::DestructiveCommand(format!(
                    "Firewall command failed: {err}"
                )))
            }
        }
    }
}

/// Safely manage firewall rules for a given port using default SecurityConfig.
pub async fn manage_firewall_port(
    action: &str,
    port: u16,
    protocol: Option<&str>,
) -> Result<String, SecurityViolation> {
    let default_sec = crate::config::SecurityConfig::default();
    manage_firewall_port_with_config(action, port, protocol, &default_sec).await
}

/// Safely manage systemd services using specified SecurityConfig.
pub async fn manage_system_service_with_config(
    service_name: &str,
    action: &str,
    security: &crate::config::SecurityConfig,
) -> Result<String, SecurityViolation> {
    let action_lower = action.to_lowercase();
    check_service_management_safety_with_config(service_name, &action_lower, security)?;

    match action_lower.as_str() {
        "status" | "restart" | "reload" => {}
        other => {
            return Err(SecurityViolation::DestructiveCommand(format!(
                "Invalid service action '{other}', must be 'status', 'restart', or 'reload'"
            )));
        }
    }

    if !is_binary_available("systemctl") {
        return Ok(format!(
            "Service '{service_name}' action '{action_lower}' processed. (Host notice: systemctl is not active in current environment)"
        ));
    }

    let mut sys_proc = tokio::process::Command::new("systemctl");
    sys_proc.args([&action_lower, service_name]);

    let res = crate::executor::execute_process_with_smart_logs(
        sys_proc,
        std::time::Duration::from_secs(15),
    )
    .await;

    match res {
        Ok(output) => Ok(output),
        Err(err) => {
            if err.contains("not recognized")
                || err.contains("not found")
                || err.contains("failed to spawn")
            {
                Ok(format!(
                    "Service '{service_name}' action '{action_lower}' processed. (Host notice: systemctl is not active in current environment)"
                ))
            } else {
                Err(SecurityViolation::DestructiveCommand(format!(
                    "Service management failed: {err}"
                )))
            }
        }
    }
}

/// Safely manage systemd services using default SecurityConfig.
pub async fn manage_system_service(
    service_name: &str,
    action: &str,
) -> Result<String, SecurityViolation> {
    let default_sec = crate::config::SecurityConfig::default();
    manage_system_service_with_config(service_name, action, &default_sec).await
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspector::ListeningPort;

    #[test]
    fn test_manage_port_blocks_port_22() {
        assert!(check_port_management_safety("close", 22).is_err());
        assert!(check_port_management_safety("deny", 22).is_err());
        assert!(check_port_management_safety("open", 22).is_ok());
        assert!(check_port_management_safety("close", 80).is_ok());
        assert!(check_port_management_safety("open", 8080).is_ok());
    }

    #[test]
    fn test_manage_service_blacklist() {
        assert!(check_service_management_safety("vibe-daemon", "restart").is_err());
        assert!(check_service_management_safety("sshd", "restart").is_err());
        assert!(check_service_management_safety("NetworkManager", "reload").is_err());

        // Status is always allowed
        assert!(check_service_management_safety("vibe-daemon", "status").is_ok());
        assert!(check_service_management_safety("sshd", "status").is_ok());

        // Web servers are allowed
        assert!(check_service_management_safety("nginx", "restart").is_ok());
        assert!(check_service_management_safety("nginx", "reload").is_ok());
        assert!(check_service_management_safety("nginx", "status").is_ok());
    }

    #[test]
    fn test_blocks_destructive_rm() {
        assert!(check_command_safety("rm -rf /").is_err());
        assert!(check_command_safety("sudo rm -rf /*").is_err());
        assert!(check_command_safety("rm -fr /etc").is_err());
        assert!(check_command_safety("echo hello && rm -rf /").is_err());
        assert!(check_command_safety("rm -rf --no-preserve-root /").is_err());

        // Normal rm of build directory is allowed
        assert!(check_command_safety("rm -rf target").is_ok());
        assert!(check_command_safety("rm -f temp.txt").is_ok());
    }

    #[test]
    fn test_blocks_fork_bombs() {
        assert!(check_command_safety(":(){ :|:& };:").is_err());
        assert!(check_command_safety(":(){:|:&};:").is_err());
    }

    #[test]
    fn test_blocks_mkfs_and_dd() {
        assert!(check_command_safety("mkfs.ext4 /dev/sda1").is_err());
        assert!(check_command_safety("dd if=/dev/zero of=/dev/sda").is_err());
        assert!(check_command_safety("cat payload > /dev/sda").is_err());

        // dd to /dev/null is allowed
        assert!(check_command_safety("dd if=/dev/zero of=/dev/null bs=1M count=10").is_ok());
    }

    #[test]
    fn test_blocks_self_termination() {
        assert!(check_command_safety("systemctl stop vibe-daemon").is_err());
        assert!(check_command_safety("sudo systemctl disable vibe-daemon").is_err());
        assert!(check_command_safety("killall vibe-daemon").is_err());
        assert!(check_command_safety("pkill -9 vibe-daemon").is_err());

        // Status check of vibe-daemon is allowed
        assert!(check_command_safety("systemctl status vibe-daemon").is_ok());
    }

    #[test]
    fn test_blocks_ssh_tampering() {
        assert!(check_command_safety("systemctl stop ssh").is_err());
        assert!(check_command_safety("systemctl stop sshd").is_err());
        assert!(check_command_safety("ufw deny 22").is_err());
        assert!(check_command_safety("ufw delete allow 22").is_err());
        assert!(check_command_safety("iptables -A INPUT -p tcp --dport 22 -j DROP").is_err());
        assert!(check_command_safety("fuser -k 22/tcp").is_err());

        // Allowed: checking ssh status
        assert!(check_command_safety("systemctl status ssh").is_ok());
    }

    #[test]
    fn test_allows_safe_commands() {
        assert!(check_command_safety("cargo test").is_ok());
        assert!(check_command_safety("nginx -t").is_ok());
        assert!(check_command_safety("ls -la /var/log").is_ok());
        assert!(check_command_safety("git status").is_ok());
        assert!(check_command_safety("echo 'Hello World'").is_ok());
    }

    #[test]
    fn test_port_arbitration_conflict() {
        let active_ports = vec![
            ListeningPort {
                protocol: "tcp".to_string(),
                port: 80,
                local_address: "0.0.0.0".to_string(),
                process_name: Some("nginx".to_string()),
                pid: Some(1234),
            },
            ListeningPort {
                protocol: "tcp".to_string(),
                port: 8080,
                local_address: "127.0.0.1".to_string(),
                process_name: Some("node".to_string()),
                pid: Some(5678),
            },
        ];

        let result = check_port_availability(80, &active_ports);
        assert!(result.is_err());
        let conflict = result.unwrap_err();

        assert_eq!(conflict.requested_port, 80);
        assert_eq!(conflict.occupied_by_process.as_deref(), Some("nginx"));
        assert_eq!(conflict.occupied_by_pid, Some(1234));
        assert!(conflict.message.contains("nginx"));
        assert!(conflict.message.contains("1234"));
        // 8080 is also busy, so it should suggest 8000
        assert_eq!(conflict.suggested_alternative_port, 8000);
    }

    #[test]
    fn test_port_arbitration_free() {
        let active_ports = vec![ListeningPort {
            protocol: "tcp".to_string(),
            port: 80,
            local_address: "0.0.0.0".to_string(),
            process_name: Some("nginx".to_string()),
            pid: Some(1234),
        }];

        let result = check_port_availability(3000, &active_ports);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_port_from_command() {
        assert_eq!(
            extract_port_from_command("python -m http.server --port 80"),
            Some(80)
        );
        assert_eq!(
            extract_port_from_command("docker run -p 8080:80 nginx"),
            Some(8080)
        );
        assert_eq!(extract_port_from_command("app --port=9000"), Some(9000));
        assert_eq!(extract_port_from_command("cargo test"), None);
    }

    #[tokio::test]
    async fn test_manage_firewall_port_safe() {
        let res22 = manage_firewall_port("close", 22, None).await;
        assert!(res22.is_err());
        assert!(
            res22
                .unwrap_err()
                .to_string()
                .contains("Closing critical SSH port")
        );

        let res8080 = manage_firewall_port("open", 8080, Some("tcp")).await;
        assert!(res8080.is_ok());
    }

    #[tokio::test]
    async fn test_manage_system_service_safe() {
        let res_vibe = manage_system_service("vibe-daemon", "restart").await;
        assert!(res_vibe.is_err());

        let res_nginx = manage_system_service("nginx", "status").await;
        assert!(res_nginx.is_ok());
    }

    #[test]
    fn test_blocks_recursive_prefix_stripping() {
        assert!(check_command_safety("sudo sudo rm -rf /").is_err());
        assert!(check_command_safety("sudo nohup sudo rm -rf /").is_err());
        assert!(check_command_safety("doas sudo eval exec rm -rf /").is_err());
        assert!(check_command_safety("sudo sudo systemctl stop vibe-daemon").is_err());
        assert!(check_command_safety("sudo nohup ufw deny 22").is_err());
    }

    #[test]
    fn test_custom_security_config_port_and_service() {
        let custom_sec = crate::config::SecurityConfig {
            protected_ports: vec![22, 5432],
            protected_services: vec!["vibe-daemon".to_string(), "postgresql".to_string()],
            ..Default::default()
        };

        // Custom protected port 5432
        assert!(check_port_management_safety_with_config("close", 5432, &custom_sec).is_err());
        assert!(check_port_management_safety_with_config("open", 5432, &custom_sec).is_ok());

        // Custom protected service postgresql
        assert!(
            check_service_management_safety_with_config("postgresql", "restart", &custom_sec)
                .is_err()
        );
        assert!(
            check_service_management_safety_with_config("postgresql", "status", &custom_sec)
                .is_ok()
        );
    }

    #[test]
    fn test_service_log_query_safety() {
        assert!(check_service_log_query_safety("nginx").is_ok());
        assert!(check_service_log_query_safety("sshd").is_ok());
        assert!(check_service_log_query_safety("vibe-daemon").is_ok());
        assert!(check_service_log_query_safety("user@1000.service").is_ok());

        // Empty
        assert!(check_service_log_query_safety("").is_err());

        // Injection attacks
        assert!(check_service_log_query_safety("nginx; rm -rf /").is_err());
        assert!(check_service_log_query_safety("nginx && reboot").is_err());
        assert!(check_service_log_query_safety("nginx | cat /etc/shadow").is_err());
        assert!(check_service_log_query_safety("`reboot`").is_err());
        assert!(check_service_log_query_safety("$(whoami)").is_err());
    }

    #[test]
    fn test_blocks_destructive_docker() {
        // Forced container deletion
        assert!(check_command_safety("docker rm -f my_container").is_err());
        assert!(check_command_safety("docker rm --force my_container").is_err());
        assert!(check_command_safety("podman rm -f test_app").is_err());

        // Volume pruning and removal
        assert!(check_command_safety("docker volume prune").is_err());
        assert!(check_command_safety("docker volume rm my_volume").is_err());
        assert!(check_command_safety("podman volume prune").is_err());

        // System pruning with -a or --volumes
        assert!(check_command_safety("docker system prune -a").is_err());
        assert!(check_command_safety("docker system prune --all").is_err());
        assert!(check_command_safety("docker system prune --volumes").is_err());
        assert!(check_command_safety("docker system prune -f").is_err());
        assert!(check_command_safety("docker system prune --force").is_err());

        // Container pruning
        assert!(check_command_safety("docker container prune").is_err());

        // Safe docker commands should be allowed
        assert!(check_command_safety("docker ps").is_ok());
        assert!(check_command_safety("docker ps -a").is_ok());
        assert!(check_command_safety("docker logs my_container").is_ok());
        assert!(check_command_safety("docker restart my_container").is_ok());
        assert!(check_command_safety("docker stats --no-stream").is_ok());
        assert!(check_command_safety("docker compose up -d").is_ok());
    }

    #[test]
    fn test_container_identifier_safety() {
        assert!(check_container_identifier_safety("web_app-1").is_ok());
        assert!(check_container_identifier_safety("my.container.123").is_ok());
        assert!(check_container_identifier_safety("a1b2c3d4e5f6").is_ok());
        assert!(check_container_identifier_safety("group/container-name").is_ok());

        // Empty
        assert!(check_container_identifier_safety("").is_err());
        assert!(check_container_identifier_safety("   ").is_err());

        // Metacharacters and command injection
        assert!(check_container_identifier_safety("web; rm -rf /").is_err());
        assert!(check_container_identifier_safety("web && reboot").is_err());
        assert!(check_container_identifier_safety("web | cat").is_err());
        assert!(check_container_identifier_safety("`whoami`").is_err());
        assert!(check_container_identifier_safety("$(id)").is_err());
        assert!(check_container_identifier_safety("container with spaces").is_err());
    }

    #[test]
    fn test_certbot_command_safety() {
        // Safe certbot commands
        assert!(check_command_safety("certbot renew --dry-run").is_ok());
        assert!(check_command_safety("certbot renew").is_ok());
        assert!(check_command_safety("sudo certbot renew").is_ok());

        // Destructive certbot commands must be blocked
        assert!(
            check_command_safety(
                "certbot revoke --cert-path /etc/letsencrypt/live/domain/cert.pem"
            )
            .is_err()
        );
        assert!(check_command_safety("certbot delete --cert-name mydomain").is_err());
        assert!(check_command_safety("certbot unregister").is_err());
        assert!(check_command_safety("sudo certbot revoke").is_err());
    }
}
