# Dhi Operations Guide

> Installation, configuration, and daily operations for Dhi

---

## Quick Install (Linux with eBPF)

Dhi uses **eBPF** to intercept SSL/TLS traffic at the kernel level. This provides full visibility into HTTPS content without certificates or proxy configuration.

### 1. Build from Source

```bash
# Clone repository
git clone https://github.com/seconize-co/dhi.git
cd dhi

# Build release binary
cargo build --release

# Binary is at: ./target/release/dhi
```

### 2. Build eBPF Program

```bash
cd bpf
clang -O2 -g -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o

# Install system-wide
sudo mkdir -p /usr/share/dhi
sudo cp dhi_ssl.bpf.o /usr/share/dhi/
```

### 3. Install Binary and Config

```bash
# Copy to system path
sudo cp target/release/dhi /usr/local/bin/

# Copy config
sudo mkdir -p /etc/dhi
sudo cp dhi.toml.example /etc/dhi/dhi.toml

# Create log directory
sudo mkdir -p /var/log/dhi
```

### 4. Verify Installation

```bash
# Check binary
dhi --version

# Check eBPF program
ls -la /usr/share/dhi/dhi_ssl.bpf.o

# Check kernel version (needs 5.4+)
uname -r
```

---

## Running Dhi (eBPF Mode)

**eBPF mode is the primary mode** - it intercepts SSL/TLS traffic at the kernel level, providing full visibility into HTTPS content.

### Production Mode Policy

For Linux production deployments:

- Run eBPF mode as the primary mode.
- Use proxy mode only as fallback/compatibility (for non-Linux or constrained environments).
- Run one mode at a time in production; avoid running both simultaneously unless explicitly required and documented.

### Start Dhi

```bash
# Start with alerts (requires root for eBPF)
sudo dhi --config /etc/dhi/dhi.toml --level alert

# With Slack notifications
sudo dhi --level alert --slack-webhook "https://hooks.slack.com/..."

# Block mode (actively block threats)
sudo dhi --level block

# Block mode with graceful termination first
sudo dhi --level block --ebpf-block-action term

# Block mode with log-only decisioning (no process signal)
sudo dhi --level block --ebpf-block-action none

# Verbose logging
sudo dhi --level alert -v
```

### eBPF Block Action

When SSL analysis returns a block decision in block mode, you can choose how Dhi enforces it:

- none: log the block decision only
- term: send SIGTERM to the process ID that produced the event
- kill: send SIGKILL to the process ID that produced the event (default)

Set this via CLI with --ebpf-block-action or in configuration:

```toml
[protection]
level = "block"
ebpf_block_action = "kill"
```

### What Happens

1. Dhi loads eBPF programs into the kernel
2. Hooks SSL library functions (SSL_read, SSL_write, etc.)
3. Captures plaintext **before encryption / after decryption**
4. Scans for secrets, PII, injection attempts
5. Alerts or blocks based on configuration (including configurable process signal action in block mode)

**No proxy configuration needed!** All applications using OpenSSL, BoringSSL, or GnuTLS are automatically monitored.

### Copilot CLI eBPF Setup (Required for reliable attribution)

For Copilot CLI validation, add the Copilot executable as an explicit SSL target and ensure logs are written to a file used by the harness.

```bash
# Discover Copilot binary path
command -v copilot
readlink -f "$(command -v copilot)"

# Example systemd override (adjust path if needed)
sudo systemctl edit dhi
```

Use this override content:

```ini
[Service]
Environment=DHI_SSL_EXTRA_TARGETS=/home/<user>/.local/bin/copilot
StandardOutput=append:/tmp/log/dhi/dhi.log
StandardError=append:/tmp/log/dhi/dhi.log
```

Then reload + restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart dhi
```

Quick verification:

```bash
grep -aE 'Found runtime SSL target|Attached uprobe_ssl_.*copilot' /tmp/log/dhi/dhi.log | tail -n 20
```

Expected:
- Copilot target discovery line.
- `Attached uprobe_ssl_*` lines for Copilot path.

---

## Proxy Mode (Limited - Hostname Only)

> ✅ Supported runtime modes today: **eBPF mode** and **proxy mode**.
>
> 🔮 **MITM mode is not supported yet** and is a future enhancement.
>
> ⚠️ **Note**: Proxy mode can only see **hostnames**, not request/response content. HTTPS traffic is encrypted end-to-end through the proxy. Use eBPF mode for full content inspection.

Proxy mode is useful for:
- macOS/Windows (where eBPF is unavailable)
- Hostname-level blocking (e.g., block access to certain APIs)
- Connection logging (which LLMs are being called)

**Default proxy port: 8080** (see `[proxy]` in dhi.toml.example)

```bash
# Start proxy (default port 8080)
dhi proxy

# Or override port for testing/specific deployments
dhi proxy --port 18080

# Configure applications to use proxy
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

| Proxy Mode Can See | Proxy Mode CANNOT See |
|-------------------|----------------------|
| ✅ Hostname (api.openai.com) | ❌ Request body (prompts) |
| ✅ Connection timing | ❌ Response body (completions) |
| ✅ Bytes transferred | ❌ Secrets/PII in payload |

---

## Service Management (systemd)

### Install as Service

Create `/etc/systemd/system/dhi.service` (or copy from `ops/systemd/dhi.service`):

```ini
[Unit]
Description=Dhi AI Agent Security
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dhi --config /etc/dhi/dhi.toml --level alert
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelModules=true
LockPersonality=true
RestrictSUIDSGID=true
ReadWritePaths=/var/log/dhi

# For eBPF mode (needs capabilities)
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

### Service Commands

```bash
# Enable on boot
sudo systemctl enable dhi

# Start service
sudo systemctl start dhi

# Stop service
sudo systemctl stop dhi

# Restart service
sudo systemctl restart dhi

# Check status
sudo systemctl status dhi

# View logs
sudo journalctl -u dhi -f

# View last 100 lines
sudo journalctl -u dhi -n 100
```

### Systemctl Portability & Edge Cases

**systemd is the standard init system across all major Linux distributions:**

| Distribution | Init System | Status |
|--------------|------------|--------|
| Ubuntu, Debian | systemd | ✅ Default (20.04+) |
| Fedora, RHEL, CentOS, AlmaLinux, Rocky | systemd | ✅ Standard |
| openSUSE, SLES | systemd | ✅ Default |
| Arch Linux | systemd | ✅ Standard |
| Alpine Linux | OpenRC | ⚠️ Minimal distro; systemd optional |

**For ~99% of production Linux (AWS, GCP, Azure, on-premises servers), systemd is available.**

#### Check if systemd is available

```bash
# Test if systemd is present
command -v systemctl >/dev/null 2>&1 && echo "systemd available" || echo "systemd NOT available"

# View init system
ps -p 1 -o comm=
```

Expected output: `systemd` or `init` (if using systemd, output is `systemd`).

#### Alpine Linux (OpenRC) - Fallback

If you deploy on Alpine or another non-systemd system:

1. **Install script gracefully skips service setup:**
   ```
   WARNING: systemd not detected; Dhi service will not be registered.
   You can still run Dhi manually: sudo dhi --level alert
   ```

2. **Manual start on reboot:**

   Create `/etc/local.d/dhi.start`:
   ```bash
   #!/bin/sh
   exec /usr/local/bin/dhi --level alert
   ```

   Make executable:
   ```bash
   sudo chmod +x /etc/local.d/dhi.start
   ```

   Alternatively, use a simple shell wrapper in your startup scripts or use `supervisord`/`runit` for service management.

3. **Recommended:** Use systemd-enabled distribution (Ubuntu 20.04+, Debian 11+, RHEL 8+) for production deployments. systemd adoption is near-universal for production workloads.

### Auto-start Setup (Verified)

If you want Dhi to start automatically after VM reboot, use this exact setup:

```bash
# Build and install binary
cargo build --release
sudo install -m 755 target/release/dhi /usr/local/bin/dhi

# Runtime directories
sudo mkdir -p /etc/dhi /var/log/dhi /usr/share/dhi
sudo cp -n dhi.toml.example /etc/dhi/dhi.toml || true

# Create systemd service
sudo tee /etc/systemd/system/dhi.service >/dev/null <<'EOF'
[Unit]
Description=Dhi AI Agent Security
After=network.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/dhi --level alert --ebpf-ssl-only --port 9090
Restart=always
RestartPreventExitStatus=73
RestartSec=5
WorkingDirectory=/var/log/dhi
UMask=0027
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelModules=true
LockPersonality=true
RestrictSUIDSGID=true
ReadWritePaths=/var/log/dhi
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

# Enable + start now
sudo systemctl daemon-reload
sudo systemctl enable --now dhi

# Verify
systemctl is-enabled dhi
systemctl status dhi --no-pager
curl http://127.0.0.1:9090/health
```

> Note: `dhi.toml.example` is a template and may not map 1:1 to the runtime config struct in this build. The service above starts Dhi via CLI flags for a reliable boot path.

Reference files in this repository:

- `ops/systemd/dhi.service` (systemd unit)
- `ops/sysctl/99-dhi-ebpf.conf` (kernel perf settings for eBPF uprobes)

---

## Crash Resistance

### Automatic Restart (systemd)

The systemd service above includes:

```ini
Restart=always          # Always restart on crash
RestartPreventExitStatus=73  # Do not loop-restart on singleton lock conflict
RestartSec=5            # Wait 5 seconds before restart
StartLimitBurst=5       # Max 5 restarts
StartLimitIntervalSec=60  # Within 60 seconds
```

This means:
- If Dhi crashes, it restarts automatically in 5 seconds
- If it crashes 5 times in 60 seconds, systemd stops trying (likely a config error)
- If startup exits with code `73` (singleton lock conflict), systemd does **not** loop-restart.

### What Happens on Crash

| Mode | Crash Behavior | Recommendation |
|------|----------------|----------------|
| **eBPF Mode** | **Fail-open**: Traffic flows normally, no protection | Acceptable - availability preserved |
| **Proxy Mode** | **Fail-closed**: Apps can't connect | Use eBPF mode, or set up failover |

### Proxy Mode Failover (Optional)

If you must use proxy mode, configure a failover:

**Option 1: PAC File (Proxy Auto-Config)**

Create `proxy.pac`:
```javascript
function FindProxyForURL(url, host) {
    // Try Dhi proxy first, fall back to direct (default port 8080)
    return "PROXY 127.0.0.1:8080; DIRECT";
}
```

**Option 2: Environment Variable Wrapper**

Create `/usr/local/bin/safe-proxy`:
```bash
#!/bin/bash
# Check if Dhi is running on default proxy port 8080
if nc -z 127.0.0.1 8080 2>/dev/null; then
    export HTTP_PROXY=http://127.0.0.1:8080
    export HTTPS_PROXY=http://127.0.0.1:8080
else
    echo "WARNING: Dhi proxy not running, proceeding without protection"
    unset HTTP_PROXY HTTPS_PROXY
fi
exec "$@"
```

Usage: `safe-proxy claude "your prompt"`

---

## Health Checks

### Check Dhi is Running

```bash
# Check process
pgrep -f dhi

# Check systemd status
systemctl is-active dhi

# Check eBPF probes (Linux)
sudo cat /sys/kernel/debug/tracing/uprobe_events | grep dhi

# Check default proxy port (proxy mode: 8080)
nc -z 127.0.0.1 8080 && echo "Proxy OK" || echo "Proxy DOWN"

# Check metrics endpoint (default port: 9090)
nc -z 127.0.0.1 9090 && echo "Metrics OK" || echo "Metrics DOWN"
```

### Health Endpoint

Dhi exposes a health endpoint:

```bash
curl http://127.0.0.1:9090/health
# Returns: {"status": "healthy", "uptime_seconds": 3600}
```

### Agent/session observability endpoint

Use `/api/agents` for framework/session attribution and runtime usage counters:

```bash
curl -s http://127.0.0.1:9090/api/agents | jq '.total_agents, .total_sessions, .total_tokens, .total_tool_calls'
```

Key fields:

- Report: `total_tokens`, `total_tool_calls`
- Per agent: `id`, `framework`, `pid`, `total_tokens`, `total_tool_calls`
- Per session: `session_id`, `session_name`, `total_tokens`, `total_tool_calls`

Session naming uses best-effort enrichment with deterministic IDs:

1. Request payload/header names
2. Environment variables (`DHI_SESSION_NAME`, `COPILOT_SESSION_NAME`, ...)
3. Copilot disk metadata (`~/.copilot/session-state/*/workspace.yaml`)
4. tmux session name from tty
5. Fallback `process@cwd(tty)`

Runtime extraction behavior notes:

- `RUN-*` markers are extracted with boundary-aware parsing over connection buffers (more reliable under fragmented/noisy payloads than simple whitespace tokenization).
- Token extraction supports common OpenAI and Anthropic usage schemas from both full JSON payloads and SSE `data:` lines.
- Tool-call extraction supports `tool_calls`, `function_call`, `tools`, and Anthropic `type:"tool_use"` patterns.
- Session usage attribution is request-scoped: token/tool increments are applied to session IDs extracted from that specific request, not broadcast to all sessions on the agent.

### Monitoring Script

Create `/usr/local/bin/dhi-health`:
```bash
#!/bin/bash
if curl -s http://127.0.0.1:9090/health | grep -q healthy; then
    echo "Dhi: HEALTHY"
    exit 0
else
    echo "Dhi: UNHEALTHY"
    systemctl restart dhi
    exit 1
fi
```

Add to cron for periodic checks:
```bash
# Check every minute
* * * * * /usr/local/bin/dhi-health >> /tmp/log/dhi/health.log 2>&1
```

---

## Configuration

### Main Config File: `/etc/dhi/dhi.toml`

```toml
[protection]
level = "alert"  # log, alert, block

[budget]
enabled = true
daily_limit = 500.0
monthly_limit = 5000.0
alert_threshold = 0.8

[alerting]
enabled = true
slack_webhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
min_severity = "medium"
rate_limit_per_minute = 30

[reporting]
enabled = true
output_dir = "/tmp/log/dhi/reports"
daily_report = true

[metrics]
enabled = true
port = 9090

[logging]
level = "info"
file = "/tmp/log/dhi/dhi.log"
```

Notes:
- Log/report paths are deployment-specific and fully configurable.
- Common choices are `/tmp/log/dhi/*` (dev/test) and `/var/log/dhi/*` (hardened production hosts).
- Use one active log root per environment (do not run both concurrently):
  - dev/test: `/tmp/log/dhi/*`
  - production: `/var/log/dhi/*`

### Environment Variables

```bash
export DHI_PROTECTION_LEVEL=alert
export DHI_SLACK_WEBHOOK=https://hooks.slack.com/...
export DHI_LOG_LEVEL=info
```

---

## Logs and Reports

### Log Locations

| File | Content |
|------|---------|
| `/tmp/log/dhi/dhi.log` (or `/var/log/dhi/dhi.log`) | Main application log |
| `/tmp/log/dhi/reports/daily-*.json` (or `/var/log/dhi/reports/daily-*.json`) | Daily security reports |
| `/tmp/log/dhi/alerts.log` (or `/var/log/dhi/alerts.log`) | Alert history |
| `journalctl -u dhi` | systemd logs |

### Log Rotation

Log rotation config is provided at:

```bash
ops/logrotate/dhi
```

Install on host:

```bash
sudo install -m 644 ops/logrotate/dhi /etc/logrotate.d/dhi
```

Validate rotation config:

```bash
sudo logrotate -d /etc/logrotate.d/dhi
```

Force a rotation run (test only):

```bash
sudo logrotate -f /etc/logrotate.d/dhi
```

Policy summary:
- `*.log`: daily, keep 14, compress.
- report `*.json`: weekly, keep 8, compress.
- covers both `/tmp/log/dhi/*` and `/var/log/dhi/*`, but operate with one active root per environment.

### View Logs

```bash
# Real-time logs
sudo journalctl -u dhi -f

# Today's logs
sudo journalctl -u dhi --since today

# Filter by severity
sudo journalctl -u dhi -p warning

# Application log
tail -f /tmp/log/dhi/dhi.log
```

### View Reports

```bash
# List reports
ls -la /tmp/log/dhi/reports/

# View latest daily report
cat /tmp/log/dhi/reports/daily-$(date +%Y-%m-%d).json | jq .

# Summary of today's events
cat /tmp/log/dhi/reports/daily-$(date +%Y-%m-%d).json | jq '.summary'
```

---

## Troubleshooting

### Dhi Won't Start

```bash
# Check for errors
sudo journalctl -u dhi -n 50

# Common issues:
# 1. Config file syntax error
dhi --config /etc/dhi/dhi.toml --check

# 2. Port already in use
sudo lsof -i :8080
sudo lsof -i :9090

# 3. Missing eBPF program
ls -la /usr/share/dhi/dhi_ssl.bpf.o

# 4. Insufficient permissions
# eBPF needs root or CAP_BPF
```

### eBPF Not Working

```bash
# Check kernel version (needs 5.4+)
uname -r

# Check BTF support
ls /sys/kernel/btf/vmlinux

# Check eBPF capabilities
capsh --print | grep bpf

# View eBPF errors
sudo dmesg | grep -i bpf
```

If logs show `perf_event_open failed` while attaching SSL uprobes, apply:

```bash
# 1) Lower perf restrictions for uprobes
echo 'kernel.perf_event_paranoid=1' | sudo tee /etc/sysctl.d/99-dhi-ebpf.conf
sudo sysctl --system | grep perf_event_paranoid

# 2) Ensure systemd unit has required capabilities
sudo cp ops/systemd/dhi.service /etc/systemd/system/dhi.service
sudo systemctl daemon-reload
sudo systemctl restart dhi
```

Verify fix:

```bash
sudo journalctl -u dhi -n 80 --no-pager | grep -E 'Attached uprobe|Failed to attach|No SSL uprobes'
```

Expected:
- `Attached uprobe_*` lines for OpenSSL/GnuTLS
- no repeated `perf_event_open failed`

If Copilot tests still fail while synthetic HTTPS works:

```bash
# Confirm Copilot marker + detection lines are present
grep -aE 'COPILOT RUN MARKER|Secrets detected|PII detected|Prompt injection detected|SSL ALERT' /tmp/log/dhi/dhi.log | tail -n 40

# Confirm stats are moving (used by copilot-cli-e2e.sh)
curl -s http://127.0.0.1:9090/api/stats
```

### No Alerts Being Sent

```bash
# Test Slack webhook
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test from Dhi"}' \
  YOUR_SLACK_WEBHOOK_URL

# Check rate limiting (might be throttled)
grep "rate_limit" /var/log/dhi/dhi.log
```

---

## Upgrade Procedure

```bash
# 1. Build new version
cd dhi && git pull && cargo build --release

# 2. Stop service
sudo systemctl stop dhi

# 3. Backup config
sudo cp /etc/dhi/dhi.toml /etc/dhi/dhi.toml.backup

# 4. Install new binary
sudo cp target/release/dhi /usr/local/bin/

# 5. Rebuild eBPF if needed
cd bpf && clang -O2 -g -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o
sudo cp dhi_ssl.bpf.o /usr/share/dhi/

# 6. Start service
sudo systemctl start dhi

# 7. Verify
sudo systemctl status dhi
curl http://127.0.0.1:9090/health
```

---

## Uninstall

```bash
# Stop and disable service
sudo systemctl stop dhi
sudo systemctl disable dhi

# Remove files
sudo rm /usr/local/bin/dhi
sudo rm /etc/systemd/system/dhi.service
sudo rm -rf /etc/dhi
sudo rm -rf /usr/share/dhi
sudo rm -rf /var/log/dhi

# Reload systemd
sudo systemctl daemon-reload
```

---

## Quick Reference

| Action | Command |
|--------|---------|
| Start | `sudo systemctl start dhi` |
| Stop | `sudo systemctl stop dhi` |
| Restart | `sudo systemctl restart dhi` |
| Status | `sudo systemctl status dhi` |
| Logs | `sudo journalctl -u dhi -f` |
| Health | `curl http://127.0.0.1:9090/health` |
| Metrics | `curl http://127.0.0.1:9090/metrics` |
| Config test | `dhi --config /etc/dhi/dhi.toml --check` |

---

## Support

- GitHub Issues: https://github.com/seconize-co/dhi/issues
- Documentation: https://github.com/seconize-co/dhi/tree/main/docs

*Dhi is open source under MIT license.*
