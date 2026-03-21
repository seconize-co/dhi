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

### Build

```bash
cargo build --release
```

### Run

```bash
# Start monitoring with alerts
./target/release/dhi --level alert --port 9090

# With Slack notifications
./target/release/dhi --level alert --slack-webhook https://hooks.slack.com/...

# Demo mode (see features in action)
./target/release/dhi demo

# Block mode (actively prevent threats)
./target/release/dhi --level block
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
| [Agentic Features](docs/AGENTIC_FEATURES.md) | Full API documentation with examples |
| [Comparison](docs/COMPARISON.md) | How Dhi compares to other tools |
| [Branding](docs/BRANDING.md) | Brand guidelines |

## Endpoints

When running, Dhi exposes:

| Endpoint | Description |
|----------|-------------|
| `GET /metrics` | Prometheus metrics |
| `GET /health` | Health check |
| `GET /api/stats` | JSON statistics |
| `GET /` | Web dashboard |

## Integration

### As a Library

```rust
use dhi::agentic::AgenticRuntime;

#[tokio::main]
async fn main() {
    let runtime = AgenticRuntime::new();
    
    // Register agent
    runtime.register_agent("my-agent", "langchain", None).await;
    
    // Track LLM calls
    let result = runtime.track_llm_call(
        "my-agent", "openai", "gpt-4",
        500, 200,  // tokens
        Some("Hello world".to_string()),
        false, vec![],
    ).await;
    
    println!("Cost: ${:.4}, Risk: {}", result.cost_usd, result.risk_score);
    
    // Track tool calls
    let tool_result = runtime.track_tool_call(
        "my-agent", "filesystem_read", "mcp",
        serde_json::json!({"path": "/etc/passwd"}),
    ).await;
    
    if !tool_result.allowed {
        println!("Blocked: {:?}", tool_result.flags);
    }
}
```

### As a Daemon

```bash
# Run as background service
./dhi --level alert --port 9090 &

# Agents interact via HTTP API
curl -X POST http://localhost:9090/api/track/llm \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "my-agent", "provider": "openai", "model": "gpt-4"}'
```

## Requirements

- **Rust 1.75+** for building
- **Linux** for eBPF kernel monitoring (optional, kernel 5.4+)
- Agentic security features work on all platforms

## Project Structure

```
dhi/
├── Cargo.toml          # Rust project configuration
├── src/
│   ├── main.rs         # CLI entry point
│   ├── lib.rs          # Library exports
│   ├── server.rs       # HTTP/metrics server
│   ├── agentic/        # AI agent security modules
│   │   ├── mod.rs
│   │   ├── llm_monitor.rs
│   │   ├── tool_monitor.rs
│   │   ├── prompt_security.rs
│   │   ├── secrets_detector.rs
│   │   ├── pii_detector.rs
│   │   ├── budget.rs
│   │   ├── alerting.rs
│   │   ├── metrics.rs
│   │   └── ...
│   ├── ebpf/           # Kernel monitoring (Linux)
│   ├── detection/      # Risk scoring engine
│   └── monitor/        # Statistics collection
├── docs/               # Documentation
└── README.md
```

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please read the code of conduct and submit PRs.

---

Built with Rust by [Seconize](https://seconize.co)
