# Dhi Operations Guide

> Installation, configuration, and daily operations for Dhi

---

## Quick Install (Linux with eBPF)

Dhi uses **eBPF** to intercept SSL/TLS traffic at the kernel level. This provides full visibility into HTTPS content without certificate injection or client reconfiguration.

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

### Verify Installation

```bash
sudo ./scripts/install-linux-release.sh --verify-only
```

For development/source builds, see [DEVELOPERS.md](DEVELOPERS.md).

---

## Running Dhi (eBPF Mode)

**eBPF mode is the primary mode** — intercepts SSL/TLS at the kernel level, full HTTPS content visibility without certificate injection.

### Start Dhi

The installer enables the service (auto-start on boot) but does not start it immediately.

Before first start, review config at `/etc/dhi/dhi.toml`.

Quick defaults to know:
- `protection.level = "alert"`
- `metrics.enabled = true`, `metrics.port = 9090` (health endpoint: `/health`)
- `logging.level = "info"`
- service is enabled, health timer is enabled (`dhi-health-check.timer`, 1-minute interval)

If you skipped Slack webhook during install, add it now before first start (if not set, Dhi still starts; check `journalctl -u dhi`, `/var/log/dhi/dhi.log` for warnings, and `/var/log/dhi/alerts.log` for local alert history):

```toml
[alerting]
enabled = true
slack_webhook = "https://hooks.slack.com/services/..."
```

Then start:

```bash
sudo systemctl start dhi
```

To run directly (without systemd):

```bash
sudo dhi --config /etc/dhi/dhi.toml
```

For defaults and tuning, see the [Configuration](#configuration) section.

**Recommended workflow:** Start in `alert` mode (default) for a few days to observe legitimate traffic and potential false positives. Once confident, transition to `block` mode and configure the block action via the [eBPF Block Action](#ebpf-block-action) subsection in Advanced.

For non-Linux compatibility, see [NON_LINUX_PROXY.md](NON_LINUX_PROXY.md).

---

## Service Management (systemd)

The release installer already installs and enables `dhi.service` on systemd hosts.
Use this section for day-2 operations.

### Service Commands

```bash
# Start/stop/restart
sudo systemctl start dhi
sudo systemctl stop dhi
sudo systemctl restart dhi

# Check status
sudo systemctl status dhi

# Check enabled on boot
sudo systemctl is-enabled dhi

# View logs
sudo journalctl -u dhi -f

# View last 100 lines
sudo journalctl -u dhi -n 100
```

## Health Checks

The installer sets up an automated health check timer that runs every minute. For a quick manual check:

```bash
# Is Dhi running?
systemctl is-active dhi

# Quick health check (service + endpoint)
sudo dhi-health-check

# Check timer status and recent runs
sudo systemctl status dhi-health-check.timer
sudo journalctl -u dhi-health-check.service -n 20
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
- Defaults: `[protection].level = "alert"` and `[logging].level = "info"`.
- Tune runtime behavior in this file (especially `[protection].level`, `[logging].level`, `[alerting]`, and `[metrics]`).
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

If Dhi won't attach SSL handlers (logs show `perf_event_open failed`):

```bash
# Lower perf restrictions for uprobes
echo 'kernel.perf_event_paranoid=1' | sudo tee /etc/sysctl.d/99-dhi-ebpf.conf
sudo sysctl --system | grep perf_event_paranoid

# Ensure systemd unit has required capabilities
sudo cp ops/systemd/dhi.service /etc/systemd/system/dhi.service
sudo systemctl daemon-reload
sudo systemctl restart dhi
```

For kernel requirements (5.4+ needed) and deep eBPF debugging, see [DEVELOPERS.md](DEVELOPERS.md#ebpf-troubleshooting--deep-debugging).

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

### Using Release Installer (Recommended)

```bash
# Upgrade using release installer
curl -sSL https://raw.githubusercontent.com/seconize-co/dhi/main/scripts/install-linux-release.sh | sudo bash

# Verify
sudo systemctl status dhi
curl http://127.0.0.1:9090/health
```

### From Source

For source builds, see [DEVELOPERS.md](DEVELOPERS.md#development-environment-setup) for build instructions, then:

```bash
# Backup config
sudo cp /etc/dhi/dhi.toml /etc/dhi/dhi.toml.backup

# Stop service, install new binary/eBPF, and start
sudo systemctl restart dhi

# Verify
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

## Advanced

### Health Check Options

The health check script supports guardrails to prevent restart flapping:

```bash
# Auto-restart after 3 consecutive failures, with 10-min cooldown between restarts
sudo dhi-health-check --restart-on-fail

# Run one check immediately via systemd
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

The host/port for the derived URL can also be overridden via `DHI_HEALTH_HOST` and `DHI_HEALTH_PORT`.

### Agent/Session Observability

```bash
curl -s http://127.0.0.1:9090/api/agents | jq '.total_agents, .total_sessions, .total_tokens, .total_tool_calls'
```

Key fields — per agent: `id`, `framework`, `pid`, `total_tokens`, `total_tool_calls`. Per session: `session_id`, `session_name`, `total_tokens`, `total_tool_calls`.

### Customize Service Flags

If you need to change runtime flags (for example protection level, verbosity, or config path), use a systemd override:

```bash
sudo systemctl edit dhi
```

Example override:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/dhi --config /etc/dhi/dhi.toml --level alert -v
```

Apply and verify:

```bash
sudo systemctl daemon-reload
sudo systemctl restart dhi
sudo systemctl status dhi --no-pager
```

### eBPF Block Action

When in block mode, set how Dhi enforces a block decision via `--ebpf-block-action` or in config:

```toml
[protection]
level = "block"
ebpf_block_action = "kill"   # none | term | kill (default)
```

- `none` — log decision only
- `term` — send SIGTERM to the offending process
- `kill` — send SIGKILL (default)

For architecture and eBPF internals, see [DEVELOPERS.md](DEVELOPERS.md#architecture-how-ebpf-works).

### Systemctl Portability & Edge Cases

The installer detects platform/init automatically:

- systemd hosts: installs and enables `dhi.service`
- Alpine/OpenRC hosts: skips systemd and prints OpenRC setup steps
- other non-systemd hosts: installs binaries/config and prints manual-run guidance

Quick check:

```bash
command -v systemctl >/dev/null 2>&1 && echo "systemd path" || echo "non-systemd path"
```

For Alpine/OpenRC, follow the exact post-install instructions printed by the installer.

Reference files in this repository:

- `ops/systemd/dhi.service` (service template)
- `ops/sysctl/99-dhi-ebpf.conf` (kernel perf settings for eBPF uprobes)

### Crash Resistance

#### Automatic Restart (systemd)

Installer-provided `dhi.service` includes:

```ini
Restart=always          # Always restart on crash
RestartPreventExitStatus=73  # Do not loop-restart on singleton lock conflict
RestartSec=5            # Wait 5 seconds before restart
StartLimitBurst=5       # Max 5 restarts
StartLimitIntervalSec=60  # Within 60 seconds
```

Behavior:
- Crashes are auto-restarted after 5 seconds
- Crash loops are capped at 5 restarts per 60 seconds
- Exit code `73` is not loop-restarted (singleton-lock protection)

Quick verification:

```bash
systemctl show dhi -p Restart -p RestartSec -p RestartPreventExitStatus -p StartLimitBurst -p StartLimitIntervalSec
```

#### What Happens on Crash

| Mode | Crash Behavior | Recommendation |
|------|----------------|----------------|
| **eBPF Mode** | **Fail-open**: Traffic flows normally, no protection | Acceptable - availability preserved |

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
