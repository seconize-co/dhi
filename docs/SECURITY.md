# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Dhi, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email security concerns to: **sashank@seconize.co**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### Severity Definitions

| Severity | Description |
|----------|-------------|
| **Critical** | Remote code execution, credential theft, complete bypass of security controls |
| **High** | Significant data exposure, denial of service, privilege escalation |
| **Medium** | Limited data exposure, partial bypass of controls |
| **Low** | Minor information disclosure, requires unlikely conditions |

## Security Best Practices for Users

### Deployment

1. **Never expose to public network**
   ```bash
   # GOOD: Bind to localhost only
   dhi proxy --port 18080  # Binds to 127.0.0.1 by default
   
   # BAD: Don't do this
   # Exposing metrics to 0.0.0.0 is disabled by default
   ```

2. **Run with least privileges**
   ```bash
   # Create dedicated user
   sudo useradd -r -s /bin/false dhi
   
   # Run as non-root where possible
   # eBPF mode needs elevated capabilities (see systemd section below)
   ```

3. **Enable blocking mode in production**
   ```bash
   dhi proxy --port 18080 --level block --block-secrets
   ```

4. **Harden the systemd service**
   Use systemd sandboxing plus only the minimum Linux capabilities required for your selected mode.
   ```ini
   [Service]
   NoNewPrivileges=false
   ProtectSystem=strict
   ProtectHome=read-only
   PrivateTmp=true
   ProtectKernelTunables=true
   ProtectControlGroups=true
   RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
   ReadWritePaths=/var/log/dhi

   # eBPF mode only: capabilities required by current implementation
   AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_NET_ADMIN
   CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_NET_ADMIN
   ```
   For complete operational examples, see `docs/OPERATIONS.md` and `ops/systemd/dhi.service`.

### Configuration

1. **Protect configuration files**
   ```bash
   chmod 600 ~/.config/dhi/config.toml
   ```

2. **Rotate Slack webhooks** regularly

3. **Review alerts** before enabling auto-blocking

### Monitoring

1. **Check logs regularly**
   ```bash
   journalctl -u dhi-proxy -f
   ```

2. **Monitor metrics** for anomalies
   ```bash
   curl http://localhost:9090/metrics
   ```

### Rogue Agent Tamper Model (Practical)

Assumption: an agent may attempt to disable Dhi (`systemctl stop dhi`, `kill`, config tampering) and then perform malicious actions.

Treat this as a host-compromise style risk and apply layered controls:

1. **Strict privilege separation**
   - Run agents as a separate unprivileged user/container.
   - Do not grant agent runtime access to `sudo`, `systemctl`, Docker socket, or host PID namespace.
   - Keep Dhi running as a dedicated service account.

2. **Service tamper resistance**
   - Enable automatic restart (`Restart=always`) and bounded restart policy.
   - Lock down service/config ownership and permissions (`root:dhi`, `chmod 640/600`).
   - Keep Dhi binary and unit file writable only by trusted admins.

3. **Independent detection if Dhi is down**
   - Alert on service stop/failure from outside the agent runtime (node monitor, SIEM, or external heartbeat).
   - Trigger high-priority incident workflow if Dhi health endpoint is unavailable.

4. **Independent network guardrails**
   - Enforce outbound firewall allowlists at host/network layer (independent of Dhi process state).
   - Use short-lived credentials and rapid key rotation so exposure window remains small.

5. **Operational drills**
   - Regularly test: "Dhi stopped unexpectedly" and verify alerting + automatic recovery.
   - Record recovery steps in runbooks and review after each drill.

## Security Features

Dhi includes these security protections:

| Feature | Description |
|---------|-------------|
| Secrets Detection | 20+ patterns for API keys, tokens, passwords |
| PII Detection | SSN, credit cards, emails, phone numbers |
| Prompt Injection | Pattern matching for injection attempts |
| Jailbreak Detection | DAN mode, developer mode, etc. |
| Budget Control | Prevent runaway LLM costs |
| Tool Risk Analysis | Block dangerous tool invocations |

## Known Limitations

1. **Supported runtime modes**: Dhi currently supports **eBPF mode** and **proxy mode** only.

   **MITM mode is not supported yet** and is tracked as a **future enhancement**.

2. **HTTPS Inspection in proxy mode**: Proxy mode currently tunnels HTTPS without payload inspection.

   **Interim mitigations (recommended now):**
   - Prefer eBPF mode on Linux for deeper runtime visibility.
   - Restrict outbound destinations with allowlists/firewall policy.
   - Keep protection level at `alert` or `block` for high-risk environments.
   - Monitor `/metrics` and alerts for unusual host/domain patterns.

3. **eBPF**: Only available on Linux. Kernel **5.4+** is supported; **5.8+** is recommended for best feature coverage. Requires elevated privileges/capabilities.

4. **Pattern-based Detection**: Can be bypassed with novel encoding or obfuscation.

   **Defense-in-depth guidance:**
   - Combine Dhi with outbound network controls and identity-based access controls.
   - Use short-lived credentials and rotate API keys frequently.
   - Add application-level schema/allowlist validation on prompts and tool inputs.
   - Review alerts continuously before enabling strict auto-blocking in production.

## Production Security Checklist

Before production rollout, confirm:

1. Dhi is bound to localhost or private network only.
2. Config files and secrets are readable only by the Dhi runtime user (`chmod 600`).
3. systemd hardening and capability bounding are enabled.
4. Protection level is set deliberately (`alert` first, then `block` after validation).
5. Slack/webhook/email alert destinations are tested and webhook secrets are rotated.
6. Metrics and logs are collected centrally and retention is configured.
7. eBPF kernel prerequisites are validated on target hosts.
8. Agent runtime cannot stop/modify Dhi service or its configuration.
9. Independent "Dhi down" alerting is enabled outside the protected host process.
10. Outbound firewall/egress controls remain effective even if Dhi is stopped.

## Security Incident Response (Operator Runbook)

If Dhi reports a critical event:

1. Capture evidence immediately (relevant logs, metrics snapshot, affected request metadata).
2. Revoke or rotate potentially exposed secrets.
3. Isolate impacted agent/workload and restrict outbound access.
4. Triage root cause (prompt injection, secret leak, tool abuse, or misconfiguration).
5. Add/adjust policies (allowlist/denylist, budget limits, blocking settings) before restoring normal traffic.
6. Document timeline and corrective actions for post-incident review.

If Dhi is disabled or unexpectedly stops:

1. Treat as potential security incident and isolate affected workload/host.
2. Restore Dhi service from trusted configuration and verify health/metrics endpoints.
3. Review system logs for stop/kill/config-change events and privilege escalation traces.
4. Rotate credentials that may have been exposed during the unprotected window.
5. Perform post-incident hardening (permission fixes, tighter isolation, additional alerts).

## Acknowledgments

We thank the security researchers who have helped improve Dhi:

- (Your name could be here!)

## PGP Key

PGP-based reporting is not currently used.
Please report vulnerabilities directly via email at **sashank@seconize.co**.
