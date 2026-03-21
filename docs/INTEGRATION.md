# Integrating Dhi with AI Coding Assistants

> How to use Dhi with Claude Code, GitHub Copilot CLI, Cursor, and other AI tools

---

## Overview

Dhi protects AI coding assistants through **two modes**:

| Mode | How It Works | HTTPS Visibility | Platform |
|------|--------------|------------------|----------|
| **Proxy Mode** | HTTP proxy intercepts traffic | Hostname only | All |
| **eBPF Mode** | Kernel-level SSL hooking | **Full plaintext** | Linux |

**Recommendation:** Use **eBPF mode on Linux** for full HTTPS visibility. Use **Proxy mode** on macOS/Windows or when root access is unavailable.

---

## Quick Start: Proxy Mode (All Platforms)

### 1. Build Dhi

```bash
cargo build --release
```

### 2. Copy and Edit Config (Optional)

```bash
# Copy sample config
cp dhi.toml.example dhi.toml

# Edit as needed
nano dhi.toml  # or your editor
```

### 3. Start Dhi Proxy

```bash
# Basic (alert only)
./target/release/dhi proxy --port 8080

# With secrets blocking
./target/release/dhi proxy --port 8080 --block-secrets

# With config file
./target/release/dhi --config dhi.toml proxy --port 8080

# With Slack alerts
./target/release/dhi proxy --port 8080 --slack-webhook "https://hooks.slack.com/..."
```

### 4. Configure Your AI Tool

```bash
# Set proxy environment variables
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# Now run your AI tool
claude                    # Claude Code
gh copilot suggest        # GitHub Copilot CLI
cursor                    # Cursor IDE
```

**That's it!** All LLM API calls are now monitored.

---

## Quick Start: eBPF Mode (Linux - Full HTTPS Visibility)

eBPF mode provides **full visibility into HTTPS traffic** by hooking SSL library functions. This captures plaintext **before encryption** and **after decryption**.

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

### 2. Run Dhi with eBPF (Requires Root)

```bash
# Run with eBPF monitoring
sudo ./target/release/dhi --level alert

# With Slack alerts
sudo ./target/release/dhi --level alert --slack-webhook "https://hooks.slack.com/..."
```

### 3. Use Your AI Tools Normally

No proxy configuration needed! Dhi captures all SSL traffic system-wide.

```bash
# These are automatically monitored
claude "Write a hello world program"
gh copilot suggest "how to parse JSON"
python my_langchain_agent.py
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

### Verify eBPF is Working

```bash
# Check if SSL probes are attached
sudo cat /sys/kernel/debug/tracing/uprobe_events

# Look for Dhi SSL interception logs
sudo journalctl -u dhi -f | grep SSL
```

---

## Proxy Mode vs eBPF Mode

| Aspect | Proxy Mode | eBPF Mode |
|--------|------------|-----------|
| **Platform** | All (Linux, macOS, Windows) | Linux only |
| **HTTPS Content** | Hostname only | Full plaintext |
| **Setup** | Env vars (`HTTP_PROXY`) | Build eBPF + root |
| **App Changes** | Need proxy env vars | None |
| **Root Required** | No | Yes |
| **Performance** | Minimal | Near-zero |

**Best Practice:**
- **Linux servers**: Use eBPF mode for full visibility
- **Developer machines**: Use Proxy mode (easier setup)
- **CI/CD**: Use Proxy mode (no root in containers)

---

## Configuration

### Configuration File (dhi.toml)

Create `dhi.toml` in the same directory as the binary, or specify path with `--config`:

```bash
dhi --config /path/to/dhi.toml proxy --port 8080
```

See `dhi.toml.example` for all options. Key settings:

```toml
[protection]
level = "alert"  # or "block"

[alerting]
slack_webhook = "https://hooks.slack.com/..."
min_severity = "high"

[budget]
global_limit = 100.0    # USD
agent_daily_limit = 10.0

[reporting]
output_dir = "./dhi-reports"
format = "json"

[proxy]
port = 8080
block_secrets = true
block_pii = false
```

### Environment Variables

Set these in your shell or `.env` file:

```bash
export DHI_PROTECTION_LEVEL=alert
export DHI_SLACK_WEBHOOK=https://hooks.slack.com/...
export DHI_MAX_BUDGET=100.0
export DHI_REPORT_DIR=./dhi-reports
```

See `.env.example` for all variables.

---

## Viewing Reports

### Report Location

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

## Do I Need Framework Integration?

**No!** Proxy mode provides protection without any code changes.

| Approach | Pros | Cons |
|----------|------|------|
| **Proxy Mode** | Zero code changes, works with any tool | Requires proxy env vars |
| **SDK Integration** | Deeper insights, custom events | Requires code changes |

For most users, **proxy mode is sufficient** because:
1. All HTTP traffic to LLM APIs is intercepted
2. Secrets and PII are scanned in requests/responses
3. Dangerous patterns are detected and blocked
4. No modification to your agents/tools needed

### When SDK Integration Might Help

You might want deeper integration if you need:
- Custom risk scoring for specific operations
- Per-tool granular permissions
- Integration with agent orchestration logic
- Custom event tracking

For SDK integration, Dhi exposes a Rust library:

```rust
use dhi::agentic::AgenticRuntime;

let runtime = AgenticRuntime::new();
runtime.register_agent("my-agent", "custom", None).await;
runtime.track_llm_call(...).await;
runtime.track_tool_call(...).await;
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

## Quick Setup Script

### Linux/macOS

Save as `setup-dhi.sh`:

```bash
#!/bin/bash
set -e

# Build Dhi
cargo build --release

# Copy config
cp dhi.toml.example dhi.toml

# Create report directory
mkdir -p dhi-reports

# Create systemd service (Linux only)
if [ -f /etc/systemd/system ]; then
  sudo tee /etc/systemd/system/dhi-proxy.service << EOF
[Unit]
Description=Dhi Security Proxy for AI Agents
After=network.target

[Service]
Type=simple
ExecStart=$(pwd)/target/release/dhi --config $(pwd)/dhi.toml proxy --port 8080
Restart=always
User=$USER
WorkingDirectory=$(pwd)

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable dhi-proxy
  sudo systemctl start dhi-proxy
fi

# Add to shell profile
echo '' >> ~/.bashrc
echo '# Dhi protection for AI tools' >> ~/.bashrc
echo 'export HTTP_PROXY=http://127.0.0.1:8080' >> ~/.bashrc
echo 'export HTTPS_PROXY=http://127.0.0.1:8080' >> ~/.bashrc

echo "✅ Dhi proxy running on port 8080"
echo "✅ Reports will be saved to ./dhi-reports/"
echo "Restart your terminal or run: source ~/.bashrc"
```

### Windows (PowerShell)

```powershell
# Build Dhi
cargo build --release

# Copy config
Copy-Item dhi.toml.example dhi.toml

# Create report directory
New-Item -ItemType Directory -Force -Path dhi-reports

# Set environment variables (User scope)
[Environment]::SetEnvironmentVariable("HTTP_PROXY", "http://127.0.0.1:8080", "User")
[Environment]::SetEnvironmentVariable("HTTPS_PROXY", "http://127.0.0.1:8080", "User")

# Start proxy (in separate terminal)
Start-Process -FilePath ".\target\release\dhi.exe" -ArgumentList "proxy --port 8080 --block-secrets"

Write-Host "✅ Dhi proxy started on port 8080"
Write-Host "✅ Restart your terminal to apply proxy settings"
```

---

## Protection Levels

| Flag | Behavior |
|------|----------|
| `--level log` | Log only, no alerts |
| `--level alert` | Log and send alerts |
| `--level block` | Log, alert, and block dangerous requests |
| `--block-secrets` | Block requests containing secrets |
| `--block-pii` | Block requests containing PII |

**Recommended workflow:**
1. Start with `--level alert` to see what's detected
2. Review alerts for false positives
3. Enable `--block-secrets` when confident
4. Add `--block-pii` if needed

---

## Verification

### Check Dhi is Running

```bash
# Linux/macOS
lsof -i :8080
# or
netstat -tlnp | grep 8080

# Windows
netstat -an | findstr 8080
```

### Test the Proxy

```bash
# Basic test
curl -x http://127.0.0.1:8080 https://httpbin.org/get

# Test secret detection (should trigger alert)
curl -x http://127.0.0.1:8080 \
  -H "Content-Type: application/json" \
  -d '{"prompt": "My API key is sk-proj-abc123"}' \
  https://httpbin.org/post
```

### View Logs

```bash
# If running manually
./target/release/dhi proxy --port 8080 -v

# If running as systemd service
journalctl -u dhi-proxy -f

# Example output
2026-03-21T08:30:01 INFO Dhi proxy listening on 127.0.0.1:8080
2026-03-21T08:30:15 WARN [ALERT] api.openai.com: Secrets detected: ["openai_api_key"]
2026-03-21T08:30:22 WARN [BLOCKED] api.anthropic.com: Credential leak blocked
```

---

## Troubleshooting

### AI Tool Not Using Proxy

```bash
# Verify env vars are set
echo $HTTP_PROXY
echo $HTTPS_PROXY

# Some tools need uppercase
export http_proxy=$HTTP_PROXY
export https_proxy=$HTTPS_PROXY
```

### HTTPS Issues

For tools with strict SSL:
```bash
export NODE_TLS_REJECT_UNAUTHORIZED=0  # Node.js tools
```

### Proxy Connection Refused

```bash
# Check if Dhi is running
ps aux | grep dhi

# Check port
netstat -tlnp | grep 8080

# Restart if needed
./target/release/dhi proxy --port 8080
```

---

## Summary

| Step | Command |
|------|---------|
| Build | `cargo build --release` |
| Configure | Edit `dhi.toml` |
| Start proxy | `dhi proxy --port 8080 --block-secrets` |
| Set proxy | `export HTTP_PROXY=http://127.0.0.1:8080` |
| Use AI tool | `claude` / `gh copilot` / etc. |
| View reports | `cat dhi-reports/daily-*.json` |
| View metrics | `curl http://127.0.0.1:9090/metrics` |

**Files Reference:**
- `dhi.toml.example` - Configuration template
- `.env.example` - Environment variables reference
- `examples/sample-report-daily.json` - Sample daily report
- `examples/sample-alert-webhook.json` - Webhook payload format
- `examples/sample-alert-slack.json` - Slack message format
