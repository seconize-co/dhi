# Integrating Dhi with AI Coding Assistants

> How to use Dhi with Claude Code, GitHub Copilot CLI, Cursor, and other AI tools

---

## Overview

**No code changes required!** Dhi protects AI tools automatically through:

| Mode | How It Works | HTTPS Visibility | Platform |
|------|--------------|------------------|----------|
| **eBPF Mode** | Kernel-level SSL hooking | **Full plaintext** | Linux |
| **Proxy Mode** | HTTP proxy intercepts traffic | Hostname only | All |

**Recommendation:** Use **eBPF mode on Linux** for full HTTPS visibility with zero configuration. Use **Proxy mode** on macOS/Windows.

---

## Quick Start: eBPF Mode (Linux - Recommended)

Just install and run - Dhi captures all SSL traffic system-wide automatically.

### 1. Build Dhi and eBPF Program

```bash
# Build Dhi
cargo build --release

# Build the eBPF program
cd bpf
clang -O2 -g -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o

# Install eBPF program
sudo mkdir -p /usr/share/dhi
sudo cp dhi_ssl.bpf.o /usr/share/dhi/
```

### 2. Run Dhi (Requires Root)

```bash
# Run with eBPF monitoring
sudo ./target/release/dhi --level alert

# With Slack alerts
sudo ./target/release/dhi --level alert --slack-webhook "https://hooks.slack.com/..."
```

### 3. Use Your AI Tools Normally

**No configuration needed!** Your tools work exactly as before.

```bash
# These are automatically protected
claude "Write a hello world program"
gh copilot suggest "how to parse JSON"
python my_langchain_agent.py
cursor .
```

### What Gets Captured

| Library | Functions Hooked |
|---------|-----------------|
| OpenSSL | `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex` |
| BoringSSL | `SSL_read`, `SSL_write` (Chrome, Go apps) |
| GnuTLS | `gnutls_record_recv`, `gnutls_record_send` |

### Requirements

- Linux kernel 5.4+ (for BTF support)
- Root or `CAP_BPF` capability
- SSL library must be dynamically linked

---

## Quick Start: Proxy Mode (macOS/Windows)

For non-Linux systems, use proxy mode with environment variables:

### 1. Start Dhi Proxy

```bash
./target/release/dhi proxy --port 8080 --block-secrets
```

### 2. Configure Environment Variables

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

### 3. Use Your AI Tools

```bash
claude "Write a hello world program"
gh copilot suggest "how to parse JSON"
```

---

## Comparison: eBPF vs Proxy Mode

| Aspect | eBPF Mode | Proxy Mode |
|--------|-----------|------------|
| **Platform** | Linux only | All |
| **Setup** | Build eBPF + root | Env vars |
| **App Changes** | **None** | Need proxy env vars |
| **HTTPS Content** | **Full plaintext** | Hostname only |
| **Root Required** | Yes | No |
| **Performance** | Near-zero | Minimal |

**Recommendation:**
- **Linux (servers, dev machines)**: Use eBPF mode
- **macOS/Windows**: Use Proxy mode
- **CI/CD containers**: Use Proxy mode (no root)

---

## Configuration

All settings in `dhi.toml` (see `dhi.toml.example` for full template):

```toml
[protection]
level = "alert"  # or "block"

[alerting]
slack_webhook = "https://hooks.slack.com/..."
min_severity = "high"

[budget]
daily_limit = 100.0
monthly_limit = 1000.0

[reporting]
output_dir = "./dhi-reports"
daily_report = true
```

Environment variables (see `.env.example`):

```bash
export DHI_PROTECTION_LEVEL=alert
export DHI_SLACK_WEBHOOK=https://hooks.slack.com/...
```

---

## Viewing Reports

Reports are saved to the configured directory (default: `./dhi-reports`):

```
dhi-reports/
├── daily-2026-03-21.json       # Daily summary
├── alerts-2026-03-21.json      # Alert log
├── agents-2026-03-21.json      # Agent statistics
└── metrics-2026-03-21.json     # Prometheus metrics snapshot
```

### Sample Reports

See `examples/` directory for sample report formats:

- `sample-report-daily.json` - Full daily security report
- `sample-alert-webhook.json` - Webhook alert payload
- `sample-alert-slack.json` - Slack message format

### Prometheus Metrics

Access metrics at `http://127.0.0.1:9090/metrics`:

```bash
curl http://127.0.0.1:9090/metrics
```

Key metrics:
- `dhi_llm_calls_total` - Total LLM API calls
- `dhi_tool_calls_total` - Total tool invocations
- `dhi_alerts_total` - Security alerts by type
- `dhi_blocked_total` - Blocked requests
- `dhi_cost_usd_total` - Estimated spending

---

## AI Tool Specific Setup

### Claude Code

```bash
# Set proxy in your shell profile (~/.bashrc or ~/.zshrc)
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# Run Claude Code
claude
```

Or create an alias:

```bash
alias claude-safe='HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080 claude'
```

### GitHub Copilot CLI

```bash
# Set proxy
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# Run Copilot CLI
gh copilot suggest "how do I..."
gh copilot explain "..."
```

### Cursor IDE

In Cursor settings (`Settings > Proxy`):
- HTTP Proxy: `http://127.0.0.1:8080`
- HTTPS Proxy: `http://127.0.0.1:8080`

### VS Code with Copilot

In VS Code settings (`settings.json`):

```json
{
  "http.proxy": "http://127.0.0.1:8080",
  "http.proxyStrictSSL": false
}
```

### Any Python AI Tool (LangChain, CrewAI, etc.)

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

python my_agent.py
```

Or in Python code:

```python
import os
os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8080'
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8080'
```

---

## What Gets Protected

| Direction | Protection |
|-----------|------------|
| **Requests (Prompts)** | |
| - Secrets in prompts | 20+ patterns: API keys, tokens, passwords |
| - PII in prompts | SSN, credit cards, emails, phones |
| - Prompt injection | Jailbreak attempts, instruction override |
| **Responses** | |
| - Secrets in output | Leaked credentials in LLM output |
| - PII in output | Sensitive data exposure |
| **SSRF Protection** | Blocks requests to internal IPs, metadata endpoints |

---

## Quick Setup Script (Linux with eBPF)

Save as `setup-dhi.sh`:

```bash
#!/bin/bash
set -e

# Build Dhi
cargo build --release

# Build eBPF program
cd bpf
clang -O2 -g -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o
cd ..

# Install eBPF program
sudo mkdir -p /usr/share/dhi
sudo cp bpf/dhi_ssl.bpf.o /usr/share/dhi/

# Copy config
cp dhi.toml.example dhi.toml

# Create report directory
mkdir -p dhi-reports

# Create systemd service
sudo tee /etc/systemd/system/dhi.service << EOF
[Unit]
Description=Dhi Security for AI Agents
After=network.target

[Service]
Type=simple
ExecStart=$(pwd)/target/release/dhi --config $(pwd)/dhi.toml --level alert
Restart=always
WorkingDirectory=$(pwd)

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable dhi
sudo systemctl start dhi

echo "✅ Dhi running with eBPF monitoring"
echo "✅ Reports will be saved to ./dhi-reports/"
echo "✅ All AI tools are now protected automatically"
```

---

## Protection Levels

| Flag | Behavior |
|------|----------|
| `--level log` | Log only, no alerts |
| `--level alert` | Log and send alerts |
| `--level block` | Log, alert, and block dangerous requests |

**Recommended workflow:**
1. Start with `--level alert` to see what's detected
2. Review alerts for false positives
3. Switch to `--level block` when confident

---

## Verification

### Check Dhi is Running

```bash
# Check service status
sudo systemctl status dhi

# Check eBPF probes (Linux)
sudo cat /sys/kernel/debug/tracing/uprobe_events
```

### View Logs

```bash
# If running as systemd service
sudo journalctl -u dhi -f

# Example output
2026-03-21T08:30:01 INFO Dhi eBPF SSL monitoring active
2026-03-21T08:30:15 WARN [ALERT] api.openai.com: Secrets detected: ["openai_api_key"]
2026-03-21T08:30:22 WARN [BLOCKED] api.anthropic.com: Credential leak blocked
```

---

## Summary

### Linux (eBPF Mode - Recommended)

| Step | Command |
|------|---------|
| Build | `cargo build --release` |
| Build eBPF | `cd bpf && clang -O2 -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o` |
| Install eBPF | `sudo cp bpf/dhi_ssl.bpf.o /usr/share/dhi/` |
| Configure | Edit `dhi.toml` |
| Run | `sudo ./target/release/dhi --level alert` |

**No further setup needed - all AI tools protected automatically!**

### macOS/Windows (Proxy Mode)

| Step | Command |
|------|---------|
| Build | `cargo build --release` |
| Configure | Edit `dhi.toml` |
| Start proxy | `./dhi proxy --port 8080` |
| Set proxy | `export HTTP_PROXY=http://127.0.0.1:8080` |
| Use AI tool | `claude` / `gh copilot` / etc. |

**Files Reference:**
- `dhi.toml.example` - Configuration template
- `.env.example` - Environment variables reference
- `examples/sample-report-daily.json` - Sample daily report
- `examples/sample-alert-webhook.json` - Webhook payload format
- `examples/sample-alert-slack.json` - Slack message format
