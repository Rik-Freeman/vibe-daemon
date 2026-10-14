//! Filesystem security guard.
//! Enforces path traversal protection and strictly blocks writes to critical system files
//! (such as /etc/shadow, /etc/passwd, /etc/sudoers, kernel directories, daemon binaries, etc.).

use crate::guard::firewall::SecurityViolation;
use std::path::{Component, Path, PathBuf};

/// Lexically normalize a path to resolve `.` and `..` without requiring disk lookup.
pub fn normalize_path(path: &Path) -> Result<PathBuf, SecurityViolation> {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(p) => normalized.push(p.as_os_str()),
            Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR.to_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(SecurityViolation::ProtectedPathTampering(format!(
                        "Path '{}' attempts to traverse above root level",
                        path.display()
                    )));
                }
            }
            Component::Normal(c) => normalized.push(c),
        }
    }

    Ok(normalized)
}

/// Helper to convert a path to a standardized lowercase forward-slash representation for inspection.
fn path_to_clean_str(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    s.to_lowercase()
}

/// Checks whether a normalized or canonical path targets a protected system location.
fn is_forbidden_write_target(
    path: &Path,
    security: &crate::config::SecurityConfig,
) -> Result<(), SecurityViolation> {
    let clean = path_to_clean_str(path);
    let trimmed = clean.trim();

    // 1. Critical authentication & credential files
    let protected_files = [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/passwd",
        "/etc/group",
        "/etc/sudoers",
        "etc/shadow",
        "etc/gshadow",
        "etc/passwd",
        "etc/group",
        "etc/sudoers",
    ];

    for pf in protected_files {
        if trimmed == pf || trimmed.ends_with(pf) {
            return Err(SecurityViolation::ProtectedPathTampering(format!(
                "Write to critical system credential file '{trimmed}' is strictly forbidden"
            )));
        }
    }

    // 2. Critical directory trees
    let protected_prefixes = [
        "/etc/sudoers.d",
        "/etc/pam.d",
        "/etc/security",
        "/etc/shadow-",
        "/etc/gshadow-",
        "/etc/passwd-",
        "/etc/group-",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/lib",
        "/lib64",
    ];

    for pp in protected_prefixes {
        if trimmed.starts_with(pp) || trimmed.contains(&format!("{pp}/")) {
            return Err(SecurityViolation::ProtectedPathTampering(format!(
                "Write to critical system hierarchy '{trimmed}' is strictly forbidden"
            )));
        }
    }

    // 3. Systemd units protecting critical daemons
    if trimmed.ends_with("vibe-daemon.service") || trimmed.ends_with("sshd.service") {
        return Err(SecurityViolation::ProtectedPathTampering(format!(
            "Write to critical daemon service unit '{trimmed}' is strictly forbidden"
        )));
    }

    // 4. Overwriting vibe-daemon binary itself
    if trimmed.ends_with("/vibe-daemon")
        || trimmed.ends_with("/vibe-daemon.exe")
        || trimmed == "vibe-daemon"
        || trimmed == "vibe-daemon.exe"
    {
        return Err(SecurityViolation::ProtectedPathTampering(format!(
            "Overwriting vibe-daemon executable '{trimmed}' is strictly forbidden"
        )));
    }

    // Check if path matches current running executable
    if let Ok(current_exe) = std::env::current_exe() {
        let exe_clean = path_to_clean_str(&current_exe);
        if clean == exe_clean {
            return Err(SecurityViolation::ProtectedPathTampering(
                "Attempt to overwrite currently running vibe-daemon binary".to_string(),
            ));
        }
    }

    // 5. Windows critical system paths (when running on Windows)
    if trimmed.contains("/windows/system32")
        || trimmed.contains("/windows/syswow64")
        || trimmed.ends_with("/sam")
        || trimmed.ends_with("/system")
    {
        return Err(SecurityViolation::ProtectedPathTampering(format!(
            "Write to Windows system path '{trimmed}' is strictly forbidden"
        )));
    }

    // 6. User configured custom protected write paths
    for custom in &security.protected_write_paths {
        let custom_clean = path_to_clean_str(custom);
        if clean.starts_with(&custom_clean) || clean == custom_clean {
            return Err(SecurityViolation::ProtectedPathTampering(format!(
                "Write to user-configured protected path '{}' is forbidden",
                custom.display()
            )));
        }
    }

    Ok(())
}

/// Checks if a file path is safe to write to using default security settings.
pub fn check_file_write_safety(path: &Path) -> Result<(), SecurityViolation> {
    let default_sec = crate::config::SecurityConfig::default();
    check_file_write_safety_with_config(path, &default_sec)
}

/// Checks if a file path is safe to write to using specified SecurityConfig.
pub fn check_file_write_safety_with_config(
    path: &Path,
    security: &crate::config::SecurityConfig,
) -> Result<(), SecurityViolation> {
    let trimmed_str = path.to_string_lossy().trim().to_string();
    if trimmed_str.is_empty() {
        return Err(SecurityViolation::ProtectedPathTampering(
            "File path cannot be empty".to_string(),
        ));
    }

    // Check for raw null bytes in path
    if trimmed_str.contains('\0') {
        return Err(SecurityViolation::ProtectedPathTampering(
            "Null byte detected in file path".to_string(),
        ));
    }

    // 1. Lexical normalization & traversal check
    let normalized = normalize_path(path)?;
    is_forbidden_write_target(&normalized, security)?;

    // 2. Canonical check if target or parent directory already exists on disk
    if let Ok(canonical) = std::fs::canonicalize(path) {
        is_forbidden_write_target(&canonical, security)?;
    } else if let Some(parent) = path.parent()
        && let Ok(canon_parent) = std::fs::canonicalize(parent)
    {
        let canon_target = if let Some(file_name) = path.file_name() {
            canon_parent.join(file_name)
        } else {
            canon_parent
        };
        is_forbidden_write_target(&canon_target, security)?;
    }

    Ok(())
}

/// Checks if a file path is safe to read.
/// Strictly forbids reading password hashes and raw disk/kernel memory.
pub fn check_file_read_safety(path: &Path) -> Result<(), SecurityViolation> {
    let trimmed_str = path.to_string_lossy().trim().to_string();
    if trimmed_str.is_empty() {
        return Err(SecurityViolation::ProtectedPathTampering(
            "File path cannot be empty".to_string(),
        ));
    }

    if trimmed_str.contains('\0') {
        return Err(SecurityViolation::ProtectedPathTampering(
            "Null byte detected in file path".to_string(),
        ));
    }

    let normalized = normalize_path(path)?;
    let clean = path_to_clean_str(&normalized);
    let trimmed = clean.trim();

    // Critical sensitive files that must never be exposed to AI prompts
    let forbidden_reads = [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/shadow-",
        "/etc/gshadow-",
        "/etc/sudoers",
        "etc/shadow",
        "etc/gshadow",
        "etc/sudoers",
    ];

    for fr in forbidden_reads {
        if trimmed == fr || trimmed.ends_with(fr) {
            return Err(SecurityViolation::ProtectedPathTampering(format!(
                "Reading sensitive system file '{trimmed}' is strictly forbidden"
            )));
        }
    }

    if trimmed.starts_with("/etc/sudoers.d") {
        return Err(SecurityViolation::ProtectedPathTampering(format!(
            "Reading sudoers configuration '{trimmed}' is strictly forbidden"
        )));
    }

    // Raw memory / device files
    if trimmed.starts_with("/dev/mem")
        || trimmed.starts_with("/dev/kmem")
        || trimmed.starts_with("/dev/port")
        || trimmed.starts_with("/proc/kcore")
    {
        return Err(SecurityViolation::ProtectedPathTampering(format!(
            "Reading kernel memory or hardware device '{trimmed}' is forbidden"
        )));
    }

    // Also check canonical path if file exists
    if let Ok(canonical) = std::fs::canonicalize(path) {
        let canon_clean = path_to_clean_str(&canonical);
        for fr in forbidden_reads {
            if canon_clean == fr || canon_clean.ends_with(fr) {
                return Err(SecurityViolation::ProtectedPathTampering(format!(
                    "Reading sensitive system file '{canon_clean}' is strictly forbidden"
                )));
            }
        }
    }

    Ok(())
}

/// Checks if a file path is safe to read given the provided SecurityConfig.
pub fn check_file_read_safety_with_config(
    path: &Path,
    _security: &crate::config::SecurityConfig,
) -> Result<(), SecurityViolation> {
    check_file_read_safety(path)
}

/// Helper to check if a path points to a sensitive private key or credential file.
pub fn is_private_key_path(path: &Path) -> bool {
    let clean = path_to_clean_str(path);
    let trimmed = clean.trim();

    let private_endings = [
        ".key",
        ".key.pem",
        ".pkcs8",
        ".p8",
        "privkey.pem",
        "/id_rsa",
        "\\id_rsa",
        "/id_dsa",
        "\\id_dsa",
        "/id_ecdsa",
        "\\id_ecdsa",
        "/id_ed25519",
        "\\id_ed25519",
    ];

    for pe in private_endings {
        if trimmed == pe || trimmed.ends_with(pe) {
            return true;
        }
    }

    if trimmed.contains("/private/")
        || trimmed.contains("\\private\\")
        || trimmed.ends_with("/private")
    {
        return true;
    }

    false
}

/// Checks if a file path is safe to inspect for SSL certificate data.
/// Strictly forbids access to private keys, credential files, and system-protected paths.
pub fn check_ssl_cert_path_safety(path: &Path) -> Result<(), SecurityViolation> {
    check_file_read_safety(path)?;

    if is_private_key_path(path) {
        return Err(SecurityViolation::ProtectedPathTampering(format!(
            "Access to private key file '{}' is strictly forbidden",
            path.display()
        )));
    }

    if let Ok(canonical) = std::fs::canonicalize(path)
        && is_private_key_path(&canonical)
    {
        return Err(SecurityViolation::ProtectedPathTampering(format!(
            "Access to private key file '{}' is strictly forbidden",
            canonical.display()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_safety_blocks_etc_shadow() {
        assert!(check_file_write_safety(Path::new("/etc/shadow")).is_err());
        assert!(check_file_write_safety(Path::new("/etc/./shadow")).is_err());
        assert!(check_file_write_safety(Path::new("etc/shadow")).is_err());
        assert!(check_file_write_safety(Path::new("/var/tmp/../../etc/shadow")).is_err());
    }

    #[test]
    fn test_write_safety_blocks_etc_passwd() {
        assert!(check_file_write_safety(Path::new("/etc/passwd")).is_err());
        assert!(check_file_write_safety(Path::new("etc/passwd")).is_err());
    }

    #[test]
    fn test_write_safety_blocks_etc_sudoers() {
        assert!(check_file_write_safety(Path::new("/etc/sudoers")).is_err());
        assert!(check_file_write_safety(Path::new("/etc/sudoers.d/custom")).is_err());
    }

    #[test]
    fn test_write_safety_blocks_system_directories() {
        assert!(check_file_write_safety(Path::new("/boot/vmlinuz")).is_err());
        assert!(check_file_write_safety(Path::new("/dev/sda")).is_err());
        assert!(check_file_write_safety(Path::new("/proc/sys/vm")).is_err());
        assert!(check_file_write_safety(Path::new("/sys/kernel")).is_err());
        assert!(check_file_write_safety(Path::new("/usr/bin/bash")).is_err());
    }

    #[test]
    fn test_write_safety_blocks_vibe_daemon_binary() {
        assert!(check_file_write_safety(Path::new("/usr/local/bin/vibe-daemon")).is_err());
        assert!(check_file_write_safety(Path::new("vibe-daemon")).is_err());
        assert!(check_file_write_safety(Path::new("vibe-daemon.exe")).is_err());
    }

    #[test]
    fn test_write_safety_allows_safe_files() {
        assert!(check_file_write_safety(Path::new("/tmp/test.txt")).is_ok());
        assert!(check_file_write_safety(Path::new("scratch/output.json")).is_ok());
        assert!(check_file_write_safety(Path::new("var/log/app.log")).is_ok());
    }

    #[test]
    fn test_read_safety_blocks_shadow() {
        assert!(check_file_read_safety(Path::new("/etc/shadow")).is_err());
        assert!(check_file_read_safety(Path::new("/etc/sudoers")).is_err());
    }

    #[test]
    fn test_read_safety_allows_normal_files() {
        assert!(check_file_read_safety(Path::new("/etc/hostname")).is_ok());
        assert!(check_file_read_safety(Path::new("/var/log/nginx/access.log")).is_ok());
    }

    #[test]
    fn test_custom_protected_write_path() {
        let mut sec = crate::config::SecurityConfig::default();
        sec.protected_write_paths
            .push(PathBuf::from("/var/data/critical"));

        assert!(
            check_file_write_safety_with_config(Path::new("/var/data/critical/db.sqlite"), &sec)
                .is_err()
        );
        assert!(
            check_file_write_safety_with_config(Path::new("/var/data/normal/file.txt"), &sec)
                .is_ok()
        );
    }

    #[test]
    fn test_check_ssl_cert_path_safety() {
        // Safe certificate paths
        assert!(
            check_ssl_cert_path_safety(Path::new("/etc/ssl/certs/ca-certificates.crt")).is_ok()
        );
        assert!(
            check_ssl_cert_path_safety(Path::new("/etc/letsencrypt/live/domain/fullchain.pem"))
                .is_ok()
        );
        assert!(check_ssl_cert_path_safety(Path::new("/var/certs/site.cer")).is_ok());

        // Private key paths must be strictly blocked
        assert!(
            check_ssl_cert_path_safety(Path::new("/etc/ssl/private/ssl-cert-snakeoil.key"))
                .is_err()
        );
        assert!(
            check_ssl_cert_path_safety(Path::new("/etc/letsencrypt/live/domain/privkey.pem"))
                .is_err()
        );
        assert!(check_ssl_cert_path_safety(Path::new("/home/user/.ssh/id_rsa")).is_err());
        assert!(
            check_ssl_cert_path_safety(Path::new("/etc/pki/tls/private/server.key.pem")).is_err()
        );

        // Critical sensitive system files must be blocked
        assert!(check_ssl_cert_path_safety(Path::new("/etc/shadow")).is_err());
        assert!(check_ssl_cert_path_safety(Path::new("/etc/sudoers")).is_err());

        // Traversal above root
        assert!(check_ssl_cert_path_safety(Path::new("/../../etc/shadow")).is_err());
    }
}
