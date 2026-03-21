# Dhi Operations Guide

> Installation, configuration, and daily operations for Dhi

---

## Quick Install

### 1. Build from Source

```bash
# Clone repository
git clone https://github.com/seconize-co/dhi.git
cd dhi

# Build release binary
cargo build --release

# Binary is at: ./target/release/dhi
```

### 2. Build eBPF Program (Linux Only)

```bash
cd bpf
clang -O2 -g -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o

# Install system-wide
sudo mkdir -p /usr/share/dhi
sudo cp dhi_ssl.bpf.o /usr/share/dhi/
```

### 3. Install Binary

```bash
# Copy to system path
sudo cp target/release/dhi /usr/local/bin/

# Copy config
sudo mkdir -p /etc/dhi
sudo cp dhi.toml.example /etc/dhi/dhi.toml

# Create log directory
sudo mkdir -p /var/log/dhi
```

---

## Running Dhi

### Option A: eBPF Mode (Recommended for Linux)

**No proxy configuration needed - works at kernel level.**

```bash
# Start (requires root)
sudo dhi --config /etc/dhi/dhi.toml --level alert

# With Slack alerts
sudo dhi --level alert --slack-webhook "https://hooks.slack.com/..."

# Block mode (actively block threats)
sudo dhi --level block
```

### Option B: Proxy Mode (All Platforms)

```bash
# Start proxy
dhi proxy --port 8080 --block-secrets

# Configure applications to use proxy
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

---

## Service Management (systemd)

### Install as Service

Create `/etc/systemd/system/dhi.service`:

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
ReadWritePaths=/var/log/dhi

# For eBPF mode (needs capabilities)
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE CAP_NET_ADMIN

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

---

## Crash Resistance

### Automatic Restart (systemd)

The systemd service above includes:

```ini
Restart=always          # Always restart on crash
RestartSec=5            # Wait 5 seconds before restart
StartLimitBurst=5       # Max 5 restarts
StartLimitIntervalSec=60  # Within 60 seconds
```

This means:
- If Dhi crashes, it restarts automatically in 5 seconds
- If it crashes 5 times in 60 seconds, systemd stops trying (likely a config error)

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
    // Try Dhi proxy first, fall back to direct
    return "PROXY 127.0.0.1:8080; DIRECT";
}
```

**Option 2: Environment Variable Wrapper**

Create `/usr/local/bin/safe-proxy`:
```bash
#!/bin/bash
# Check if Dhi is running
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

# Check proxy port (proxy mode)
nc -z 127.0.0.1 8080 && echo "Proxy OK" || echo "Proxy DOWN"
```

### Health Endpoint

Dhi exposes a health endpoint:

```bash
curl http://127.0.0.1:9090/health
# Returns: {"status": "healthy", "uptime_seconds": 3600}
```

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
* * * * * /usr/local/bin/dhi-health >> /var/log/dhi/health.log 2>&1
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
| `/var/log/dhi/dhi.log` | Main application log |
| `/var/log/dhi/reports/daily-*.json` | Daily security reports |
| `/var/log/dhi/alerts.log` | Alert history |
| `journalctl -u dhi` | systemd logs |

### View Logs

```bash
# Real-time logs
sudo journalctl -u dhi -f

# Today's logs
sudo journalctl -u dhi --since today

# Filter by severity
sudo journalctl -u dhi -p warning

# Application log
tail -f /var/log/dhi/dhi.log
```

### View Reports

```bash
# List reports
ls -la /var/log/dhi/reports/

# View latest daily report
cat /var/log/dhi/reports/daily-$(date +%Y-%m-%d).json | jq .

# Summary of today's events
cat /var/log/dhi/reports/daily-$(date +%Y-%m-%d).json | jq '.summary'
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
