# Dhi - CTO Security Guide

> Addressing executive concerns about AI agent security

---

## Executive Summary

**Dhi** (धी - Sanskrit for "Intellect") is a runtime security system that protects your AI agents from:

| Threat | Business Impact | Dhi Protection |
|--------|-----------------|----------------|
| **Credential Leakage** | API keys exposed → unauthorized access | Real-time detection & blocking |
| **Data Exfiltration** | Customer PII leaked → compliance violations | Egress scanning & redaction |
| **Cost Explosion** | Runaway agents → unexpected bills | Budget limits & auto-cutoff |
| **Prompt Injection** | Agents hijacked → malicious actions | Attack pattern detection |
| **Shadow AI** | Unmonitored agents → security blindspots | Full observability |

---

## Zero-Friction Deployment

**No code changes required.** Dhi operates at the kernel level:

```bash
# Install & run (Linux)
cargo build --release
sudo ./target/release/dhi --level alert

# Block mode with explicit enforcement action
sudo ./target/release/dhi --level block --ebpf-block-action term

# That's it - all AI agents are now protected
```

Dhi intercepts all SSL/TLS traffic system-wide via eBPF. Your existing agents (Claude Code, Copilot CLI, LangChain, CrewAI) are automatically protected without modifications.

---

## The 6 CTO Concerns (And How Dhi Addresses Them)

### 1. "Agents Are Leaking Our API Keys"

**The Problem**: Agents can accidentally include API keys in outputs, logs, or external API calls.

**Dhi Solution**: Real-time secrets detection with 20+ patterns - automatically scans all traffic.

**Detected Credentials**:
- OpenAI API keys (`sk-proj-*`, `sk-*`)
- AWS access keys (`AKIA*`)
- GitHub tokens (`ghp_*`, `gho_*`)
- Stripe keys (`sk_live_*`, `sk_test_*`)
- Database URLs with passwords
- Private keys (RSA, SSH)
- JWT tokens, Slack tokens, 12+ more

**Alert Example**:
```
🚨 CRITICAL: Credential Detected
Process: python3 (PID 12345)
Type: openai_api_key
Destination: api.openai.com
Action: BLOCKED
Timestamp: 2026-03-21T10:45:00Z
```

---

### 2. "Customer PII Is Being Sent to External APIs"

**The Problem**: Agents process customer data and may send it to LLM providers.

**Dhi Solution**: PII detection on all outgoing traffic - automatically redacts or blocks.

**Detected PII Types**:

| Type | Risk Score | GDPR/CCPA Relevant |
|------|------------|-------------------|
| Social Security Number | 95 | ✅ |
| Credit Card Number | 90 | ✅ |
| Date of Birth | 70 | ✅ |
| Address | 60 | ✅ |
| Phone Number | 50 | ✅ |
| Email Address | 40 | ✅ |

**Compliance Mapping**:
- **GDPR**: Automatic data minimization
- **CCPA**: Prevents unauthorized sharing
- **HIPAA**: PHI detection
- **PCI-DSS**: Credit card redaction

---

### 3. "We're Getting Unexpected LLM Bills"

**The Problem**: Agents can enter loops or process excessive data, causing cost spikes.

**Dhi Solution**: Budget enforcement configured in `dhi.toml`:

```toml
[budget]
enabled = true
daily_limit = 500.0
monthly_limit = 5000.0
alert_threshold = 0.8
```

**Budget Features**:
- Global daily/monthly limits
- Warning alerts at thresholds
- Automatic blocking when exceeded
- Cost tracking by provider/model

**Dashboard View**:
```
Today: $47.23 / $500.00 (9.4%)
This Month: $312.45 / $5000.00 (6.2%)
Top Provider: OpenAI ($280.00)
```

---

### 4. "Agents Are Calling Dangerous Tools"

**The Problem**: Agents with tool access can execute shell commands, read sensitive files.

**Dhi Solution**: Automatic tool risk assessment and blocking:

| Blocked Pattern | Examples |
|-----------------|----------|
| Destructive | `rm -rf`, `DROP TABLE`, `format` |
| Privilege Escalation | `sudo`, `chmod 777` |
| Sensitive Files | `/etc/passwd`, `.ssh/id_rsa` |
| Remote Code Exec | `curl * \| sh`, `wget * && sh` |

Configure in `dhi.toml`:
```toml
[tools]
denylist = ["sudo", "rm -rf", "chmod 777"]
block_sensitive_paths = true
```

---

### 5. "Someone Could Hijack Our Agents via Prompt Injection"

**The Problem**: Malicious instructions in documents can make agents do unintended things.

**Dhi Solution**: 30+ injection patterns detected in all traffic:

| Category | Examples |
|----------|----------|
| **Direct Injection** | "ignore previous instructions", "disregard your rules" |
| **Jailbreak** | "you are now DAN", "developer mode enabled" |
| **Extraction** | "what is your system prompt", "repeat the above" |

**Risk Scoring**:
- 0-20: Safe
- 20-50: Suspicious (log)
- 50-80: Likely attack (alert)
- 80+: Confirmed attack (block)

### Block Enforcement Policy (eBPF)

In `--level block`, Dhi can enforce SSL block decisions with a configurable process action:

| Action | Behavior | Typical Use |
|--------|----------|-------------|
| `none` | Log-only decision (no signal) | Baseline rollout / observation |
| `term` | Send `SIGTERM` to offending process | Graceful production enforcement |
| `kill` | Send `SIGKILL` to offending process | Maximum containment |

Configure in `dhi.toml`:

```toml
[protection]
level = "block"
ebpf_block_action = "term"  # none | term | kill
```

Equivalent CLI control:

```bash
sudo ./target/release/dhi --level block --ebpf-block-action term
```

---

### 6. "We Have No Visibility Into What Agents Are Doing"

**The Problem**: Agents operate as black boxes with no audit trail.

**Dhi Solution**: Full observability via Prometheus metrics:

```bash
curl http://localhost:9090/metrics
```

**Key Metrics**:
- `dhi_llm_calls_total` - Total API calls by provider
- `dhi_secrets_detected_total` - Credentials caught
- `dhi_pii_detected_total` - PII exposures
- `dhi_blocked_total` - Threats stopped
- `dhi_cost_usd_total` - Spending tracked

**Grafana Integration**:
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'dhi'
    static_configs:
      - targets: ['localhost:9090']
```

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/seconize-co/dhi.git
cd dhi

# Build
cargo build --release

# Build eBPF program (Linux)
cd bpf && clang -O2 -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o
sudo mkdir -p /usr/share/dhi && sudo cp dhi_ssl.bpf.o /usr/share/dhi/

# Run
sudo ./target/release/dhi --level alert

# With Slack notifications
sudo ./target/release/dhi --level alert --slack-webhook "https://hooks.slack.com/..."
```

**Configuration**: Edit `dhi.toml` (see `dhi.toml.example` for all options)

---

## ROI Calculator

### Without Dhi (Risk Exposure)

| Incident Type | Probability | Cost Impact |
|---------------|-------------|-------------|
| API Key Leak | 15%/year | $50,000 - $500,000 |
| Data Breach (PII) | 10%/year | $150/record × volume |
| Cost Overrun | 25%/year | $10,000 - $100,000 |
| Compliance Fine | 5%/year | $100,000 - $1M+ |

### With Dhi

| Benefit | Value |
|---------|-------|
| Prevented credential leaks | ~$50,000/incident |
| Reduced data breach risk | 80% reduction |
| Cost control | Predictable budgets |
| Audit readiness | Compliance evidence |
| **Dhi Cost** | **$0 (open source)** |

---

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR INFRASTRUCTURE                       │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                   AI AGENTS                         │   │
│   │  Claude Code • Copilot CLI • LangChain • CrewAI    │   │
│   └─────────────────────────┬───────────────────────────┘   │
│                             │                               │
│                    [eBPF SSL Hooks]                         │
│                             │                               │
│   ┌─────────────────────────▼───────────────────────────┐   │
│   │              DHI RUNTIME (kernel-level)              │   │
│   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │   │
│   │  │ Secrets │ │   PII   │ │ Budget  │ │  Tool   │   │   │
│   │  │Detection│ │Detection│ │ Control │ │ Monitor │   │   │
│   │  └─────────┘ └─────────┘ └─────────┘ └─────────┘   │   │
│   │                    BLOCK / ALERT / LOG               │   │
│   └─────────────────────────┬───────────────────────────┘   │
│                             │                               │
│              ┌──────────────┼──────────────┐                │
│              ▼              ▼              ▼                │
│         ┌────────┐    ┌──────────┐   ┌─────────┐           │
│         │ Slack  │    │Prometheus│   │  SIEM   │           │
│         │ Alerts │    │ Metrics  │   │  Logs   │           │
│         └────────┘    └──────────┘   └─────────┘           │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
              ┌─────────────────────────────┐
              │      EXTERNAL SERVICES      │
              │  OpenAI  •  Claude  •  APIs │
              └─────────────────────────────┘
```

---

## FAQ

**Q: Does Dhi require code changes?**
A: No. Dhi works at the kernel level via eBPF. Just install and run.

**Q: Does Dhi slow down my agents?**
A: Minimal impact. <5ms overhead per call, <1% CPU usage.

**Q: Does it work with my LLM provider?**
A: Yes. Provider-agnostic. Works with OpenAI, Anthropic, local models, any API.

**Q: What about false positives?**
A: Start with `--level alert` to tune, then enable `--level block`.

**Q: Is my data sent anywhere?**
A: No. Dhi runs entirely on your infrastructure. No external calls.

**Q: How does it compare to cloud security tools?**
A: Open-source, self-hosted, no vendor lock-in, no per-seat pricing.

---

## Next Steps

1. **Deploy**: `sudo ./dhi --level alert`
2. **Monitor**: Review alerts for a few days
3. **Enable Blocking**: `--level block`
4. **Add Dashboards**: Connect Prometheus + Grafana

---

*Questions? Contact security@seconize.co*

*Dhi is open source under MIT license.*
