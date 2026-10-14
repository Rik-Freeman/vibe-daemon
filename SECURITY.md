# Security Policy

## Reporting a Vulnerability

We take the security of `vibe-daemon` seriously. If you believe you have discovered a vulnerability, security flaw, or bypass in guard mechanisms, please report it privately.

**Please DO NOT open a public issue or discuss the vulnerability publicly before it has been addressed.**

### How to Report

1. **GitHub Private Vulnerability Reporting (Preferred):**  
   Navigate to the [Security Advisories tab](https://github.com/Rik-Freeman/vibe-daemon/security/advisories) of the repository and click **"Report a vulnerability"**.
2. **Private Direct Contact:**  
   If GitHub Private Vulnerability Reporting is unavailable, please contact the repository owner privately via GitHub profile communication channels.

### Response Time & Expectations

- **Initial Response:** You can expect an initial acknowledgment within **48 hours**.
- **Assessment & Triage:** We will investigate and provide status updates as we develop and verify a resolution.
- **Coordinated Disclosure:** We ask that security researchers coordinate with us on disclosure timing until a patch is committed.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Security Model & Operational Warnings

> [!WARNING]
> **Administrative & Privileged Operations:** `vibe-daemon` executes system administration commands, inspects host state, and modifies configurations on behalf of AI models. It is designed with strict guardrails (Command Firewall, Filesystem Guard, Rate Limiting, Fail-closed Audit Trail), but defense in depth remains essential.

When deploying and operating `vibe-daemon`:
1. **Principle of Least Privilege:**  
   Run the daemon with the minimum necessary OS privileges. Restrict `sudo` rules to only explicitly authorized commands.
2. **Network Isolation & Loopback Binding:**  
   When using HTTP or SSE transports, bind to loopback interfaces (`127.0.0.1` / `::1`) whenever possible.
3. **Mandatory Authentication:**  
   Binding to external or non-loopback network interfaces requires configuring a non-empty `auth_token` in the `[security]` configuration section (`Authorization: Bearer <token>`). Unauthenticated remote binds are rejected fail-closed.
4. **Filesystem Boundaries:**  
   Strictly restrict `allowed_config_dirs` to only the directories intended for inspection and modification. Do not grant write access to system root or critical authentication paths (`/etc/shadow`, `/etc/sudoers`, `/boot`).
