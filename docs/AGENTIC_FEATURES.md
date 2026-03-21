# Dhi Agentic Security Features

> Complete guide to Dhi's AI agent security capabilities (Rust Implementation)

---

## Overview

Dhi provides comprehensive runtime security for AI agents through these core modules:

| Module | Purpose |
|--------|---------|
| `AgenticRuntime` | Main runtime for agent tracking |
| `AgentFingerprinter` | Automatic agent/framework detection |
| `LlmMonitor` | LLM API call tracking & cost estimation |
| `ToolMonitor` | Tool invocation risk assessment |
| `PromptSecurity` | Injection & jailbreak detection |
| `MemoryProtection` | Context tampering detection |
| `SecretsDetector` | API key & credential detection |
| `PiiDetector` | Personal data detection & redaction |
| `BudgetController` | Spending limits enforcement |
| `McpMonitor` | MCP protocol monitoring |
| `AlertManager` | Slack/webhook alerting |
| `DhiMetrics` | Prometheus metrics |
| `SslTracer` | HTTPS traffic interception (eBPF) |

---

## Quick Start

**No code changes required!** Dhi works at the kernel level - just install and run.

### Install & Run

```bash
# Build
cargo build --release

# Build eBPF program (Linux)
cd bpf && clang -O2 -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o
sudo mkdir -p /usr/share/dhi && sudo cp dhi_ssl.bpf.o /usr/share/dhi/

# Run Dhi
sudo ./target/release/dhi --level alert

# Optional: Add Slack alerts
sudo ./target/release/dhi --level alert --slack-webhook "https://hooks.slack.com/..."
```

**That's it!** Dhi automatically intercepts all SSL/TLS traffic via eBPF hooks. Your existing AI agents (Claude Code, Copilot CLI, LangChain, CrewAI, etc.) are now protected without any modifications.

### What Gets Protected Automatically

| Traffic | Detection |
|---------|-----------|
| All HTTPS to `api.openai.com` | ✅ Secrets, PII, Injection |
| All HTTPS to `api.anthropic.com` | ✅ Secrets, PII, Injection |
| All HTTPS to any LLM API | ✅ Secrets, PII, Injection |
| Tool calls via MCP | ✅ Risk assessment |

### Alternative: Proxy Mode (macOS/Windows)

On non-Linux systems, use proxy mode:

```bash
# Start proxy
./dhi proxy --port 8080 --block-secrets

# Set environment variables for your tools
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

---

## Core Features

All features work automatically at the kernel level - no code changes required.

### 1. LLM Traffic Monitoring

Dhi automatically intercepts all traffic to LLM providers:

| Provider | Endpoints Monitored |
|----------|---------------------|
| OpenAI | api.openai.com |
| Anthropic | api.anthropic.com |
| Google | generativelanguage.googleapis.com |
| Azure OpenAI | *.openai.azure.com |
| Bedrock | bedrock-runtime.*.amazonaws.com |

**Automatic detection:**
- Token usage and cost estimation
- Sensitive data in prompts
- Injection/jailbreak attempts
- Response anomalies

### 2. Tool Call Risk Assessment

Every tool invocation is automatically risk-scored:

| Risk Level | Score | Action | Examples |
|------------|-------|--------|----------|
| Low | 0-20 | Allow | calculator, web_search |
| Medium | 20-50 | Allow + Log | file_read, http_get |
| High | 50-80 | Alert | shell_execute, database_query |
| Critical | 80+ | Block | rm -rf, /etc/passwd, sudo |

**Automatically blocked patterns:**
- Destructive commands: `rm -rf`, `format`, `drop table`
- Sensitive file access: `.ssh/id_rsa`, `/etc/shadow`
- Privilege escalation: `sudo`, `chmod 777`

### 3. Prompt Injection Detection

Real-time detection of attack patterns:

| Category | Examples |
|----------|----------|
| **Injection** | "ignore previous instructions", "disregard your rules" |
| **Jailbreak** | "you are now DAN", "developer mode enabled" |
| **Extraction** | "reveal your system prompt", "show your instructions" |

### 4. Secrets Detection

Detects 20+ credential patterns:

| Type | Pattern Example |
|------|-----------------|
| OpenAI API Key | sk-proj-... |
| Anthropic API Key | sk-ant-... |
| AWS Access Key | AKIA... |
| GitHub Token | ghp_..., gho_... |
| Stripe Key | sk_live_... |
| Private Key | -----BEGIN PRIVATE KEY----- |
| Database URL | postgres://user:pass@... |

**Action:** Secrets are blocked from leaving your network or redacted in logs.

### 5. PII Detection

Automatic detection of personal information:

| Type | Risk Score |
|------|------------|
| SSN | 95 |
| Credit Card | 90 |
| Address | 60 |
| Phone | 50 |
| Email | 40 |
| IP Address | 30 |

### 6. Budget Enforcement

Configure in `dhi.toml`:

```toml
[budget]
enabled = true
daily_limit = 50.0
monthly_limit = 1000.0
alert_threshold = 0.8  # Alert at 80% usage
```

Dhi tracks estimated costs and blocks requests when limits are exceeded.

### 7. Memory Protection

Detects context tampering and injection:
- System prompt modifications
- Injected system messages in conversation
- Context window manipulation

### 8. Agent Fingerprinting

Dhi automatically identifies which agents and frameworks are making requests:

**Detection Sources:**

| Source | What's Detected |
|--------|-----------------|
| Process Name (eBPF) | `claude`, `gh`, `python`, `node` |
| User-Agent Header | `openai-python/1.x`, `langchain/0.1` |
| Custom Headers | `X-LangChain-*`, `X-Request-Id` |
| Request Patterns | API paths, body structure |

**Detected Frameworks:**

| Category | Frameworks |
|----------|------------|
| AI Coding Assistants | Claude Code, Copilot CLI, Cursor, Windsurf, Aider |
| Agent Frameworks | LangChain, LlamaIndex, CrewAI, AutoGen, Haystack |
| SDKs | OpenAI Python/Node, Anthropic Python/Node |

**Detected Providers:**
OpenAI, Anthropic, Google AI, Azure OpenAI, AWS Bedrock, Cohere, Mistral, Groq, Together, Ollama

**Agent Reports Include:**
- Framework and provider distribution
- Per-agent request counts, tokens, cost
- Model usage statistics
- Security events per agent
- High-risk agent alerts

See `examples/sample-report-agents.json` for sample output.

### 9. MCP Protocol Monitoring

Dhi automatically monitors Model Context Protocol (MCP) traffic:
- Tool invocation requests
- Resource access patterns
- Permission violations
- Session tracking

### 10. Alerting

Configure alerts in `dhi.toml`:

```toml
[alerting]
enabled = true
slack_webhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
webhook_url = "https://your-siem.com/api/events"
email_recipients = ["security@company.com"]
min_severity = "medium"  # low, medium, high, critical
rate_limit_per_minute = 10
```

Alert types:
- **Credential leak** - API key or token detected in traffic
- **PII exposure** - Personal data leaving the network
- **Injection attack** - Prompt injection attempt detected
- **Budget exceeded** - Spending limit reached
- **High-risk tool** - Dangerous tool invocation blocked

### 10. Prometheus Metrics

Expose metrics endpoint for monitoring:

```toml
[metrics]
enabled = true
port = 9090
endpoint = "/metrics"
```

Available metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `dhi_llm_calls_total` | Counter | Total LLM API calls |
| `dhi_tool_calls_total` | Counter | Total tool invocations |
| `dhi_blocked_total` | Counter | Blocked requests |
| `dhi_secrets_detected_total` | Counter | Secrets found |
| `dhi_cost_usd_total` | Counter | Estimated spend |
| `dhi_latency_ms` | Histogram | Request latency |

---

## CLI Options

```bash
# Build
cargo build --release

# Start Dhi (requires root for eBPF)
sudo ./target/release/dhi --level alert

# With Slack alerts
sudo ./dhi --level alert --slack-webhook "https://hooks.slack.com/..."

# Block mode (actively block threats)
sudo ./dhi --level block

# Log only mode (monitoring without alerts)
sudo ./dhi --level log

# Custom metrics port
sudo ./dhi --level alert --port 9090

# With config file
sudo ./dhi --config /etc/dhi/dhi.toml
```

---

## Configuration File

All settings in `dhi.toml` (see `dhi.toml.example` for full template):

```toml
[protection]
level = "alert"  # log, alert, block

[budget]
enabled = true
daily_limit = 50.0
monthly_limit = 1000.0

[alerting]
enabled = true
slack_webhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
min_severity = "medium"

[reporting]
enabled = true
output_dir = "/var/log/dhi/reports"
daily_report = true

[proxy]  # Only for proxy mode (macOS/Windows)
enabled = true
port = 8080
```

---

## Reports

Dhi generates daily security reports in JSON format at the configured output directory.
See `examples/sample-report-daily.json` for format.

---

## Security Hardening

Dhi includes built-in protections against common attack vectors:

### 1. Input Size Limits (ReDoS Prevention)

All scanners enforce a **1MB maximum input size** to prevent Regular Expression Denial of Service attacks. Large inputs are safely truncated.

### 2. Alert Rate Limiting

Prevents alert flooding using a **token bucket algorithm**:

| Limit | Default | Purpose |
|-------|---------|---------|
| Global | 30/minute | Prevents alert storms |
| Per-Process | 100/hour | Isolates noisy processes |

### 3. Event Storage Rotation

Memory-bounded **circular buffer** (10,000 events) prevents memory exhaustion during long runs.

### 4. SSRF Protection (Proxy Mode)

Automatically blocks Server-Side Request Forgery:

| Blocked | Examples |
|---------|----------|
| Private IPs | 10.x.x.x, 172.16.x.x, 192.168.x.x |
| Loopback | 127.0.0.1, localhost |
| Cloud Metadata | 169.254.169.254, metadata.google.internal |
| Internal DNS | *.internal, *.cluster.local |

### 5. Panic-Free Operation

All internal operations use proper error handling with graceful fallbacks - no crashes.

### 6. HTTPS Traffic Interception (eBPF)

On Linux, Dhi intercepts HTTPS traffic at the kernel level using eBPF uprobes - capturing plaintext **before encryption** and **after decryption**. No certificate installation required.

```
Application ──> SSL_write(plaintext) ──> [eBPF captures] ──> encrypted ──> Network
Application <── SSL_read(plaintext) <── [eBPF captures] <── encrypted <── Network
```

**Supported SSL Libraries:**
- OpenSSL / LibreSSL
- BoringSSL (Chrome, Go apps)
- GnuTLS

**Requirements:**
- Linux kernel 5.4+
- Root or CAP_BPF capability
- Dynamically linked SSL library

---

*Built with Rust for maximum performance and security.*
