# 🛡️ Dhi - Runtime Security for AI Agents

**धी** (Sanskrit: *Intellect* | *Perception* | *Clear Vision*)

Dhi is a **security-first runtime protection system** for AI agents. It detects and blocks credential leaks, PII exposure, prompt injection, and runaway costs—before damage is done.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://kernel.org/)

## Why Dhi?

AI agents are powerful but introduce **serious security risks**:

| Threat | Impact | Dhi Protection |
|--------|--------|----------------|
| 🔓 **Credential Leakage** | API keys exposed in logs/outputs | Real-time detection & blocking |
| 📤 **Data Exfiltration** | PII/secrets sent to external APIs | Egress scanning & redaction |
| 💸 **Cost Explosion** | Runaway LLM spending | Budget limits & auto-cutoff |
| 🔄 **Infinite Loops** | Stuck agents burning tokens | Loop detection & termination |
| 💉 **Prompt Injection** | Malicious instructions hijack agent | Attack pattern detection |
| 🔓 **Jailbreaks** | Safety bypasses via social engineering | Jailbreak signature matching |

**Dhi watches everything your agents do and stops threats in real-time.**

## Security Features

| Feature | Description |
|---------|-------------|
| 🔐 **Secrets Detection** | 20+ patterns for API keys (OpenAI, AWS, GitHub, Stripe, etc.) |
| 🛡️ **PII Protection** | Detects & redacts emails, SSNs, credit cards, phone numbers |
| 💰 **Budget Control** | Per-agent and global spending limits with auto-blocking |
| 🔍 **Tool Monitoring** | Risk-scores every tool call, blocks dangerous operations |
| 💉 **Prompt Security** | Injection and jailbreak detection with 30+ attack patterns |
| 📊 **Prometheus Metrics** | 22 security metrics for Grafana dashboards |
| 🚨 **Real-time Alerts** | Slack, email, and webhook integrations |
| 🐧 **eBPF Monitoring** | Kernel-level syscall tracking (Linux) |

## Quick Start

### Rust (Recommended)

```bash
cd dhi-rs
cargo build --release
./target/release/dhi --help
```

```bash
# Start monitoring with Slack alerts
dhi --level alert --port 9090 --slack-webhook https://hooks.slack.com/...

# Demo mode
dhi demo
```

### Python (Prototyping)

```bash
pip install bcc  # Linux only
python dhi_agentic.py --demo
```

## Architecture

```
                            ┌─────────────────────────────────────┐
                            │         EXTERNAL SERVICES           │
                            │  ┌─────────┐ ┌─────────┐ ┌───────┐  │
                            │  │ OpenAI  │ │ Claude  │ │ Tools │  │
                            │  │   API   │ │   API   │ │  MCP  │  │
                            │  └────▲────┘ └────▲────┘ └───▲───┘  │
                            └───────┼──────────┼──────────┼───────┘
                                    │          │          │
                    ════════════════╪══════════╪══════════╪════════════════
                                    │    DHI SECURITY LAYER    │
                    ════════════════╪══════════╪══════════╪════════════════
                                    │          │          │
                            ┌───────┴──────────┴──────────┴───────┐
                            │           DHI RUNTIME               │
                            │  ┌────────────────────────────────┐ │
                            │  │      SECURITY CHECKS           │ │
                            │  │  • Secrets Detection (20+)     │ │
                            │  │  • PII Scanning & Redaction    │ │
                            │  │  • Prompt Injection Detection  │ │
                            │  │  • Tool Risk Assessment        │ │
                            │  │  • Budget Enforcement          │ │
                            │  │  • Egress Control              │ │
                            │  └────────────────────────────────┘ │
                            │                 │                   │
                            │    ┌────────────┴────────────┐      │
                            │    │  BLOCK │ ALERT │ LOG    │      │
                            │    └────────────┬────────────┘      │
                            │                 │                   │
                            │  ┌──────────────┴──────────────┐    │
                            │  │   Slack  │  Prometheus  │ SIEM   │
                            │  └─────────────────────────────┘    │
                            └───────────────────▲─────────────────┘
                                                │
                    ════════════════════════════╪══════════════════════════
                                                │
                            ┌───────────────────┴─────────────────┐
                            │            AI AGENTS                │
                            │  ┌─────────┐ ┌─────────┐ ┌───────┐  │
                            │  │LangChain│ │ CrewAI  │ │AutoGen│  │
                            │  │  Agent  │ │  Agent  │ │ Agent │  │
                            │  └─────────┘ └─────────┘ └───────┘  │
                            └─────────────────────────────────────┘
```

**How it works:**
1. **AI Agents** make requests to LLM APIs and tools
2. **Dhi intercepts** all outbound requests and responses
3. **Security checks** scan for secrets, PII, injections, risky tools
4. **Action taken**: Block (stop request), Alert (notify + allow), or Log (record only)
5. **Alerts flow** to Slack, Prometheus metrics, or your SIEM

## Documentation

| Document | Description |
|----------|-------------|
| [CTO Guide](docs/CTO_GUIDE.md) | Executive guide addressing security concerns |
| [Agentic Features](docs/AGENTIC_FEATURES.md) | Detailed feature documentation |
| [Comparison](docs/COMPARISON.md) | How Dhi compares to E2B, Modal, NVIDIA |
| [Rust Implementation](dhi-rs/README.md) | Rust implementation details |

## Endpoints

When running, Dhi exposes:

| Endpoint | Description |
|----------|-------------|
| `GET /metrics` | Prometheus metrics |
| `GET /health` | Health check |
| `GET /api/stats` | JSON statistics |
| `GET /` | Web dashboard |

## Integration

### LangChain

```python
from dhi_agentic import DhiAgenticRuntime

dhi = DhiAgenticRuntime()
dhi.register_agent("my-agent", framework="langchain")

# Wrap your LLM calls
result = dhi.track_llm_call(
    agent_id="my-agent",
    provider="openai",
    model="gpt-4",
    prompt="Hello world"
)

if result["blocked"]:
    print("Request blocked:", result["reason"])
```

### MCP (Model Context Protocol)

```python
# Dhi automatically monitors MCP tool calls
result = dhi.track_tool_call(
    agent_id="my-agent",
    tool_name="filesystem_read",
    protocol="mcp",
    arguments={"path": "/etc/passwd"}
)
# Returns: {"allowed": False, "risk_level": "critical"}
```

## Requirements

- **Linux** for eBPF monitoring (kernel 5.4+)
- **Rust 1.75+** for the Rust implementation
- **Python 3.8+** for the Python implementation
- Agentic features work on any platform

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please read the code of conduct and submit PRs.

---

Built with Rust by [Seconize](https://seconize.co)
