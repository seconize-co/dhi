# Dhi Operations Guide

> Installation, configuration, and daily operations for Dhi

---

## Overview

Dhi uses **eBPF** to intercept SSL/TLS traffic at the kernel level. This provides full visibility into HTTPS content without certificate injection or client reconfiguration.

---

# BASIC OPERATIONS

## Install

### Quick Install (Release)

For production Linux deployments, use the release installer:

```bash
# Download and run installer
curl -sSL https://raw.githubusercontent.com/seconize-co/dhi/main/scripts/install-linux-release.sh | sudo bash
```

The installer automatically:
- Installs Dhi binary to `/usr/local/bin/dhi`
- Installs eBPF object to `/usr/share/dhi/dhi_ssl.bpf.o`
- Copies config template to `/etc/dhi/dhi.toml` (first install only)
- Sets up systemd service with proper capabilities
- Configures log rotation with logrotate
- Enables health check timer (runs every 1 minute)

That's it! The service is now ready to start.

---

## Start Dhi

### Default Start (Recommended)

Before starting, review config defaults at `/etc/dhi/dhi.toml`:
- Protection level: `alert` (monitors only, no blocking)
- Logging level: `info`
- Metrics port: `9090` (health endpoint: `/health`)
- Health timer: enabled (auto-restarts on failure)

Start the service:

```bash
sudo systemctl start dhi
```

**First-time workflow:** Start in `alert` mode to observe legitimate traffic for a few days before transitioning to `block` mode. See [Advanced: Block Mode](#advanced-block-mode) for details.

### Optional: Configure Slack Webhook

If you skipped the webhook during install, add it now (otherwise skip this):

```toml
[alerting]
enabled = true
slack_webhook = "https://hooks.slack.com/services/..."
```

Then restart:

```bash
sudo systemctl restart dhi
```

### Direct Run (Without systemd)

For debugging or custom setups:

```bash
sudo dhi --config /etc/dhi/dhi.toml
```

---

## Health Checks

### Quick Status Checks

The installer sets up an automated health check timer that runs every minute.

Check service status:

```bash
# Is Dhi running?
systemctl is-active dhi

# Quick health check (service + endpoint)
sudo dhi-health-check

# Check recent timer runs
sudo systemctl status dhi-health-check.timer
sudo journalctl -u dhi-health-check.service -n 10
```

### View Service Logs

```bash
# Real-time logs
sudo journalctl -u dhi -f

# Last 50 lines
sudo journalctl -u dhi -n 50
```

---

## Logs and Reports

### Where Are the Logs?

| Location | Content |
|----------|---------|
| `journalctl -u dhi` | systemd service logs |
| `/var/log/dhi/dhi.log` | Main application log |
| `/var/log/dhi/alerts.log` | Alert history (Slack webhook) |
| `/var/log/dhi/reports/daily-*.json` | Daily security reports |

### Viewing Logs

```bash
# Real-time logs
sudo journalctl -u dhi -f

# Today's logs
sudo journalctl -u dhi --since today

# Application log file
tail -f /var/log/dhi/dhi.log

# Check for alerts
tail -f /var/log/dhi/alerts.log
```

### Viewing Reports

```bash
# View today's report
cat /var/log/dhi/reports/daily-$(date +%Y-%m-%d).json | jq .

# Summary of today's alerts
cat /var/log/dhi/reports/daily-$(date +%Y-%m-%d).json | jq '.summary'
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
output_dir = "/var/log/dhi/reports"
daily_report = true

[metrics]
enabled = true
port = 9090

[logging]
level = "info"
file = "/var/log/dhi/dhi.log"
```

**Defaults:**
- Protection: `alert` (logs only)
- Logging: `info` (standard verbosity)
- Metrics port: `9090`

To change settings, edit `/etc/dhi/dhi.toml` and restart:

```bash
sudo systemctl restart dhi
```

### Common Configuration Changes

**Increase logging verbosity:**
```toml
[logging]
level = "debug"
```

**Enable block mode (after observation period):**
```toml
[protection]
level = "block"
ebpf_block_action = "kill"  # See Advanced section for options
```

**Disable Slack alerts:**
```toml
[alerting]
enabled = false
```

### Environment Variables (Optional)

You can also set these via environment variables:

```bash
export DHI_PROTECTION_LEVEL=alert
export DHI_LOG_LEVEL=info
export DHI_SLACK_WEBHOOK=https://hooks.slack.com/...
```

---

# ADVANCED OPERATIONS

## Advanced: Install

### Verify Installation

```bash
sudo ./scripts/install-linux-release.sh --verify-only
```

### Install from Source

For development/custom builds, see [DEVELOPERS.md](DEVELOPERS.md).

---

## Advanced: Start Dhi

### Service Management Commands

```bash
# Start/stop/restart
sudo systemctl start dhi
sudo systemctl stop dhi
sudo systemctl restart dhi

# Check if enabled on boot
sudo systemctl is-enabled dhi

# View full service status
sudo systemctl status dhi --no-pager
```

### Customize Runtime Flags

To override config settings via systemd, use:

```bash
sudo systemctl edit dhi
```

Add overrides:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/dhi --config /etc/dhi/dhi.toml --level alert -v
```

Apply and verify:

```bash
sudo systemctl daemon-reload
sudo systemctl restart dhi
```

### Run Directly (Debugging)

For troubleshooting, run without systemd:

```bash
sudo dhi --config /etc/dhi/dhi.toml --level debug
```

---

## Advanced: Health Checks

### Health Check Script Options

The health check script supports guardrails to prevent restart flapping:

```bash
# Auto-restart after 3 consecutive failures, with 10-min cooldown
sudo dhi-health-check --restart-on-fail

# Run one check immediately
sudo systemctl start dhi-health-check.service
```

Full options:

| Option | Default | Env var |
|--------|---------|---------|
| `--url <url>` | derived from `dhi.toml` | — |
| `--config <path>` | `/etc/dhi/dhi.toml` | `DHI_CONFIG` |
| `--health-scheme <value>` | `http` | `DHI_HEALTH_SCHEME` |
| `--health-path <path>` | `/health` | `DHI_HEALTH_PATH` |
| `--service <name>` | `dhi` | — |
| `--timeout <seconds>` | `5` | — |
| `--failures-before-restart <n>` | `3` | — |
| `--restart-cooldown <seconds>` | `600` | — |
| `--state-dir <path>` | `/run/dhi-health-check` | — |
| `--restart-on-fail` | off | — |
| `--no-systemd-check` | off | — |

Override host/port:

```bash
export DHI_HEALTH_HOST=127.0.0.1
export DHI_HEALTH_PORT=9090
sudo dhi-health-check
```

### Agent/Session Observability

Query agent and session metrics:

```bash
curl -s http://127.0.0.1:9090/api/agents | jq '.total_agents, .total_sessions, .total_tokens, .total_tool_calls'
```

Key fields per agent: `id`, `framework`, `pid`, `total_tokens`, `total_tool_calls`.
Per session: `session_id`, `session_name`, `total_tokens`, `total_tool_calls`.

---

## Advanced: Logs and Reports

### Log Rotation (Production)

Log rotation is pre-configured. Install on host:

```bash
sudo install -m 644 ops/logrotate/dhi /etc/logrotate.d/dhi
```

Validate:

```bash
sudo logrotate -d /etc/logrotate.d/dhi
```

Test rotation:

```bash
sudo logrotate -f /etc/logrotate.d/dhi
```

**Policy:**
- `*.log`: daily, keep 14 days, compress
- `*.json` reports: weekly, keep 8 weeks, compress

### Advanced Log Filtering

```bash
# Filter by severity
sudo journalctl -u dhi -p error

# Filter by time window
sudo journalctl -u dhi --since "2 hours ago"

# Follow new logs with verbose output
sudo journalctl -u dhi -f -o verbose

# Search for specific pattern
sudo journalctl -u dhi | grep "error"
```

### Report Processing

```bash
# List all reports
ls -la /var/log/dhi/reports/

# Pretty-print report
cat /var/log/dhi/reports/daily-$(date +%Y-%m-%d).json | jq '.' | less

# Extract specific field (e.g., total events)
cat /var/log/dhi/reports/daily-$(date +%Y-%m-%d).json | jq '.summary.total_events'

# Archive old reports
tar czf dhi-reports-$(date +%Y%m%d).tar.gz /var/log/dhi/reports/
```

---

## Advanced: Configuration

### Block Mode

When ready to enforce blocking (after observation period):

```toml
[protection]
level = "block"
ebpf_block_action = "kill"   # none | term | kill (default)
```

**Block action types:**
- `none` — log decision only (no enforcement)
- `term` — send SIGTERM to offending process
- `kill` — send SIGKILL (default, immediate termination)

For eBPF internals and architecture, see [DEVELOPERS.md](DEVELOPERS.md#architecture-how-ebpf-works).

### Budget and Alerts

Fine-tune alert sensitivity:

```toml
[budget]
enabled = true
daily_limit = 500.0      # Tokens per day
monthly_limit = 5000.0   # Tokens per month
alert_threshold = 0.8    # Alert at 80% usage

[alerting]
enabled = true
slack_webhook = "..."
min_severity = "medium"  # low, medium, high, critical
rate_limit_per_minute = 30  # Max alerts per minute
```

### Custom Log Paths

For non-standard deployments:

```toml
[logging]
level = "info"
file = "/custom/path/dhi.log"

[reporting]
enabled = true
output_dir = "/custom/path/reports"

[alerting]
enabled = true
```

Ensure directories exist and are writable:

```bash
sudo mkdir -p /custom/path
sudo chown dhi:dhi /custom/path
sudo chmod 755 /custom/path
```

---

## Advanced: Service & Deployment

### Systemctl Portability

The installer detects platform/init automatically:

- **systemd hosts**: installs and enables `dhi.service`
- **Alpine/OpenRC hosts**: prints manual setup steps
- **Other hosts**: prints binary installation and manual-run guidance

Quick check:

```bash
command -v systemctl >/dev/null 2>&1 && echo "systemd" || echo "non-systemd"
```

For Alpine/OpenRC, follow post-install instructions from installer.

### Automatic Restart on Crash

The systemd service includes crash recovery:

```ini
Restart=always          # Always restart
RestartPreventExitStatus=73  # Don't loop-restart on lock conflict
RestartSec=5            # Wait 5 seconds before restart
StartLimitBurst=5       # Max 5 restarts
StartLimitIntervalSec=60  # Within 60 seconds
```

Verify:

```bash
systemctl show dhi -p Restart -p RestartSec -p StartLimitBurst -p StartLimitIntervalSec
```

**Behavior:**
- Crashes auto-restart after 5 seconds
- Crash loops capped at 5 restarts per 60 seconds
- Exit code 73 (singleton lock) prevents restart loop

### Non-Linux Compatibility

For non-Linux proxy mode, see [NON_LINUX_PROXY.md](NON_LINUX_PROXY.md).

### Production Hardening

Before deploying to production, review the complete security guide: [SECURITY.md](SECURITY.md)

**Quick hardening checklist:**

1. **Protect configuration files**
   ```bash
   sudo chmod 600 /etc/dhi/dhi.toml
   sudo chown dhi:dhi /etc/dhi/dhi.toml
   ```

2. **Create dedicated service user**
   ```bash
   sudo useradd -r -s /bin/false dhi
   sudo chown -R dhi:dhi /var/log/dhi
   sudo chown -R dhi:dhi /etc/dhi
   ```

3. **Enable systemd security hardening**

   The installer provides a hardened systemd service at `ops/systemd/dhi.service`. Key hardening features:
   - `ProtectSystem=strict` — immutable filesystem
   - `ProtectHome=read-only` — read-only home
   - `PrivateTmp=true` — private /tmp
   - `NoNewPrivileges=true` — prevent privilege escalation
   - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` — network isolation
   - `CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN` — minimum eBPF capabilities

   Verify systemd hardening:
   ```bash
   sudo systemctl cat dhi.service | grep -E "Protect|Private|NoNew|Restrict|Capability"
   ```

4. **Enable protection in production**

   Start in `alert` mode for observation, then transition to `block` mode:
   ```toml
   [protection]
   level = "block"
   ebpf_block_action = "kill"
   ```

5. **Rotate Slack webhook secrets regularly**
   ```bash
   # Update webhook URL in config
   sudo nano /etc/dhi/dhi.toml
   # [alerting]
   # slack_webhook = "https://hooks.slack.com/..."
   
   sudo systemctl restart dhi
   ```

6. **Monitor logs and metrics continuously**
   ```bash
   # Real-time alerting
   sudo journalctl -u dhi -f | grep -E "ERROR|CRITICAL"
   
   # Metrics collection (feed to SIEM/monitoring)
   curl -s http://127.0.0.1:9090/metrics
   ```

7. **Set up external monitoring**
   - Monitor Dhi service health from outside the host (node exporter, SIEM)
   - Alert if `/health` endpoint becomes unreachable
   - Ensure firewall rules persist even if Dhi stops

For complete production checklist and incident response procedures, see [SECURITY.md](SECURITY.md#production-security-checklist).

---

## Troubleshooting

### Dhi Won't Start

```bash
# Check systemd logs
sudo journalctl -u dhi -n 50

# Verify config syntax
dhi --config /etc/dhi/dhi.toml --check

# Check if ports are in use
sudo lsof -i :9090

# Verify eBPF object exists
ls -la /usr/share/dhi/dhi_ssl.bpf.o

# Check permissions (needs root or CAP_BPF)
sudo -u dhi dhi --config /etc/dhi/dhi.toml 2>&1 | head -20
```

**Port Already In Use:**

If the metrics port (default `9090`) is already in use by another process, Dhi will fail to start with an error like `address already in use`.

Solution options:

```bash
# Option 1: Find and stop the conflicting process
sudo lsof -i :9090
# Kill the process using that port
sudo kill -9 <PID>

# Option 2: Change the metrics port in config
# Edit /etc/dhi/dhi.toml:
# [metrics]
# port = 9091  # Use a different port

# Then restart
sudo systemctl restart dhi

# Verify
curl http://127.0.0.1:9091/health
```

### eBPF Not Working

If logs show `perf_event_open failed`:

```bash
# Lower perf restrictions
echo 'kernel.perf_event_paranoid=1' | sudo tee /etc/sysctl.d/99-dhi-ebpf.conf
sudo sysctl --system | grep perf_event_paranoid

# Ensure systemd unit has capabilities
sudo cp ops/systemd/dhi.service /etc/systemd/system/dhi.service
sudo systemctl daemon-reload
sudo systemctl restart dhi
```

**Requirements:** Linux 5.4+ kernel, CAP_BPF capability.

See [DEVELOPERS.md](DEVELOPERS.md#ebpf-troubleshooting--deep-debugging) for deep debugging.

### No Alerts Sent

```bash
# Test webhook manually
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test from Dhi"}' \
  YOUR_SLACK_WEBHOOK_URL

# Check webhook in config
grep slack_webhook /etc/dhi/dhi.toml

# Look for rate-limiting
grep "rate_limit\|throttle" /var/log/dhi/dhi.log

# Check alert severity threshold
grep "min_severity" /etc/dhi/dhi.toml
```

---

## Upgrade Procedure

### Using Release Installer

```bash
curl -sSL https://raw.githubusercontent.com/seconize-co/dhi/main/scripts/install-linux-release.sh | sudo bash

# Verify
sudo systemctl status dhi
curl http://127.0.0.1:9090/health
```

### From Source

```bash
# Backup config
sudo cp /etc/dhi/dhi.toml /etc/dhi/dhi.toml.backup

# Build and restart
cd /path/to/dhi
cargo build --release
sudo cp target/release/dhi /usr/local/bin/
sudo systemctl restart dhi

# Verify
sudo systemctl status dhi
curl http://127.0.0.1:9090/health
```

---

## Uninstall

```bash
# Stop and disable
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
