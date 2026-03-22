# धी Dhi - Runtime Security for AI Agents

**धी** (Sanskrit: *Intellect* | *Perception*)

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

## Comparison Highlights

Dhi is positioned as a runtime security layer for AI agents, complementing (not replacing) guardrails and sandboxing tools.

- **Unique HTTPS visibility**: Dhi can inspect HTTPS traffic with eBPF SSL hooks on Linux, without installing a MITM CA certificate.
- **Broader runtime coverage**: Detects secrets, PII, prompt injection/jailbreak attempts, risky tool calls, and budget abuse in one system.
- **Kernel + application context**: Combines syscall-level telemetry and SSL/TLS interception for deeper visibility than app-layer-only tools.
- **Low-overhead protection**: Designed for fast, deterministic checks suitable for always-on production enforcement.
- **Defense-in-depth friendly**: Pairs well with conversational guardrails and code sandboxes in layered security architectures.

For complete matrices, benchmarks, and tool-by-tool comparisons, see [docs/COMPARISON.md](docs/COMPARISON.md).

## Security Features

| Feature | Description |
|---------|-------------|
| 🔐 **Secrets Detection** | 20+ patterns for API keys (OpenAI, AWS, GitHub, Stripe, etc.) |
| 🛡️ **PII Protection** | Detects & redacts emails, SSNs, credit cards, phone numbers |
| 💰 **Budget Control** | Per-agent and global spending limits with auto-blocking |
| 🔍 **Tool Monitoring** | Risk-scores every tool call, blocks dangerous operations |
| 💉 **Prompt Security** | Injection and jailbreak detection with 30+ attack patterns |
| 🔎 **Agent Fingerprinting** | Auto-detect frameworks (LangChain, CrewAI, Claude Code, etc.) |
| 📊 **Prometheus Metrics** | 22 security metrics for Grafana dashboards |
| 🚨 **Real-time Alerts** | Slack, email, and webhook integrations |
| 🐧 **eBPF Monitoring** | Kernel-level syscall tracking (Linux) |
| 🔒 **HTTPS Interception** | SSL/TLS traffic capture via eBPF uprobes (Linux) |

### Hardening Features

| Protection | Description |
|------------|-------------|
| 📏 **Input Size Limits** | 1MB max for regex scanners (ReDoS prevention) |
| 🚦 **Alert Rate Limiting** | Token bucket algorithm (30/min global, 100/hr per-agent) |
| 🔄 **Event Rotation** | Circular buffer with 10K max events (memory DoS prevention) |
| 🌐 **SSRF Protection** | Blocks private IPs and cloud metadata endpoints in proxy |
| ⚡ **Panic-Free** | All lock operations handle poisoned locks gracefully |

## Quick Start

**No code changes required!** Dhi uses eBPF to intercept SSL/TLS at the kernel level.

**Production policy**: On Linux, run **eBPF mode as the primary mode**. Proxy mode is a fallback/compatibility mode and is typically used only on platforms where eBPF is unavailable.

### Build & Run (Linux)

```bash
# Build Dhi
cargo build --release

# Build eBPF program
cd bpf && clang -O2 -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o
sudo mkdir -p /usr/share/dhi && sudo cp dhi_ssl.bpf.o /usr/share/dhi/

# Run Dhi (requires root for eBPF)
sudo ./target/release/dhi --level alert

# With Slack notifications
sudo ./target/release/dhi --level alert --slack-webhook "https://hooks.slack.com/..."
```

**That's it!** All your AI agents are now protected automatically. Full HTTPS visibility without certificates.

### Proxy Mode (macOS/Windows - Limited)

> ⚠️ Proxy mode only sees **hostnames**, not content. HTTPS is encrypted end-to-end. Use eBPF mode on Linux for full inspection.
>
> ⚠️ In production, run **one mode at a time**. Do not run both eBPF and proxy mode together unless you have a specific, documented operational reason.

```bash
# Start proxy (hostname-level monitoring only)
./target/release/dhi proxy --port 8080

# Configure your tools
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          EXTERNAL SERVICES                                  │
│     ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
│     │  OpenAI API  │    │ Anthropic API│    │  Tools/MCP   │               │
│     └──────▲───────┘    └──────▲───────┘    └──────▲───────┘               │
└────────────┼───────────────────┼───────────────────┼────────────────────────┘
             │                   │                   │
             │              HTTPS Traffic            │
             │                   │                   │
┌────────────┴───────────────────┴───────────────────┴────────────────────────┐
│                                                                             │
│                     ╔═══════════════════════════════╗                       │
│                     ║    DHI SECURITY PROXY         ║                       │
│                     ║    (HTTP Proxy + eBPF SSL)    ║                       │
│                     ╚═══════════════════════════════╝                       │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                      SECURITY SCANNING                             │    │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │    │
│  │  │  Secrets    │ │    PII      │ │  Prompt     │ │    Tool     │  │    │
│  │  │  Detection  │ │  Detection  │ │  Injection  │ │    Risk     │  │    │
│  │  │  (20+ types)│ │  & Redact   │ │  Detection  │ │  Assessment │  │    │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘  │    │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                  │    │
│  │  │   Budget    │ │    SSRF     │ │   eBPF SSL  │                  │    │
│  │  │   Control   │ │  Protection │ │  Intercept  │                  │    │
│  │  └─────────────┘ └─────────────┘ └─────────────┘                  │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                    ┌───────────────┼───────────────┐                        │
│                    │  ✋ BLOCK   │  🚨 ALERT  │  📝 LOG │                   │
│                    └───────────────┴───────────────┘                        │
│                                    │                                        │
│             ┌──────────────────────┼──────────────────────┐                 │
│             │   Slack   │   Prometheus   │   Webhook/SIEM │                 │
│             └──────────────────────┴──────────────────────┘                 │
│                                                                             │
└─────────────────────────────────────────▲───────────────────────────────────┘
                                          │
                              HTTP_PROXY / eBPF Hooks
                                          │
┌─────────────────────────────────────────┴───────────────────────────────────┐
│                              AI AGENTS                                      │
│     ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
│     │ Claude Code  │    │ Copilot CLI  │    │  LangChain   │               │
│     │              │    │              │    │   CrewAI     │               │
│     └──────────────┘    └──────────────┘    └──────────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
```

**How it works:**
1. **AI Agents** configure `HTTP_PROXY=http://127.0.0.1:8080` (or Dhi uses eBPF hooks)
2. **Dhi intercepts** all traffic to LLM APIs as a security proxy
3. **Security checks** scan for secrets, PII, injections, risky tools
4. **Action taken**: Block (stop request), Alert (notify + allow), or Log (record only)
5. **Alerts flow** to Slack, Prometheus metrics, or your SIEM

## Documentation

| Document | Description |
|----------|-------------|
| [Operations Guide](docs/OPERATIONS.md) | **Start here** - Install, start, stop, troubleshoot |
| [Agentic Features](docs/AGENTIC_FEATURES.md) | Complete feature documentation |
| [Integration Guide](docs/INTEGRATION.md) | Setup for Claude Code, Copilot CLI, etc. |
| [CTO Guide](docs/CTO_GUIDE.md) | Executive security guide |
| [Testing Guide](docs/TESTING.md) | Manual acceptance test cases for alert/block release validation |
| [Comparison](docs/COMPARISON.md) | How Dhi compares to other tools |

## Crash Resistance

| Mode | On Crash | Behavior |
|------|----------|----------|
| **eBPF Mode** | Traffic flows normally | **Fail-open** (recommended) |
| **Proxy Mode** | Apps lose connectivity | **Fail-closed** |

**Recommendation**: Use eBPF mode on Linux as the primary production mode; use proxy mode only as fallback/compatibility. The systemd service auto-restarts Dhi within 5 seconds if it crashes. See [Operations Guide](docs/OPERATIONS.md) for details.

## Endpoints

When running, Dhi exposes:

| Endpoint | Description |
|----------|-------------|
| `GET /metrics` | Prometheus metrics |
| `GET /health` | Health check |
| `GET /api/stats` | JSON statistics |

## Configuration

All settings in `dhi.toml` (see `dhi.toml.example` for full template):

```toml
[protection]
level = "alert"  # log, alert, block
ebpf_block_action = "kill"  # none, term, kill

[budget]
daily_limit = 500.0
monthly_limit = 5000.0

[alerting]
slack_webhook = "https://hooks.slack.com/..."
min_severity = "high"
```

In block mode, eBPF SSL enforcement can be configured:

- none: log only, do not send process signals
- term: send SIGTERM to the offending process
- kill: send SIGKILL to the offending process (default)

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
