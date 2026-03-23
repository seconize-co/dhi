# धी Dhi - Runtime Security for AI Agents

**धी** (Sanskrit: *Intellect* | *Perception*)

Dhi is a **security-first runtime protection system** for AI agents. It detects and blocks credential leaks, PII exposure, prompt injection, and runaway costs—before damage is done.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://kernel.org/)

## Why Dhi?

AI agents are powerful but introduce **serious security risks**:

| Threat | Impact | Dhi Protection | OWASP LLM Top 10 |
|--------|--------|----------------|-------------------|
| 🔓 **Credential Leakage** | API keys exposed in logs/outputs | Real-time detection & blocking | LLM06 Sensitive Information Disclosure |
| 📤 **Data Exfiltration** | PII/secrets sent to external APIs | Egress scanning & redaction | LLM06 Sensitive Information Disclosure |
| 💸 **Cost Explosion** | Runaway LLM spending | Budget limits & auto-cutoff | LLM04 Model DoS |
| 🔄 **Infinite Loops** | Stuck agents burning tokens | Loop detection & termination | LLM04 Model DoS |
| 💉 **Prompt Injection** | Malicious instructions hijack agent | Attack pattern detection | LLM01 Prompt Injection |
| 🔓 **Jailbreaks** | Safety bypasses via social engineering | Jailbreak signature matching | LLM01 Prompt Injection |

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

> Dhi is framework-agnostic for core security controls; framework-specific logic is primarily used in the agent fingerprinting feature.
> Security checks can be customized through config toggles and optional external pattern rule files.

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

### Install from GitHub Releases (No Compile)

Download prebuilt binaries from GitHub Releases instead of building from source.
GitHub Releases currently publish Linux binaries only.

Use the install script (downloads the correct Linux artifact for your CPU, installs `dhi`, and installs `dhi_ssl.bpf.o`):

```bash
# from a cloned repo
./scripts/install-linux-release.sh v1.0.0

# or one-liner (without cloning first)
curl -fsSL https://raw.githubusercontent.com/seconize-co/dhi/main/scripts/install-linux-release.sh | bash -s -- v1.0.0
```

Hybrid eBPF mode (recommended) keeps the bundled object for fast installs and optionally rebuilds on the host when toolchain/kernel BTF are available:

```bash
# Auto (default): try host rebuild, fall back to bundled object
DHI_REBUILD_EBPF=auto ./scripts/install-linux-release.sh v1.0.0

# Require host rebuild (fails install if rebuild fails)
./scripts/install-linux-release.sh v1.0.0 --rebuild-ebpf

# Never rebuild; always use bundled object
./scripts/install-linux-release.sh v1.0.0 --no-rebuild-ebpf
```

For macOS/Windows proxy-mode notes, see [docs/NON_LINUX_PROXY.md](docs/NON_LINUX_PROXY.md).

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

### Post-install checklist (recommended)

What the install script now does by default (production-oriented):
- creates `/var/log/dhi` and `/var/log/dhi/reports`
- installs `/etc/logrotate.d/dhi` (when available)
- validates logrotate policy and checks scheduler presence
- installs and enables systemd service (when systemd is available)

Default Dhi runtime behavior is still:
- logs -> stdout/journald (`[logging].file` unset)
- reports -> `/var/log/dhi/reports` (`[reporting].output_dir`)

**To start Dhi** (if systemd service was installed):

```bash
# Start now
sudo systemctl start dhi

# Check status
systemctl status dhi

# Follow logs in real-time
sudo journalctl -u dhi -f
```

If you want production file paths, set these in config:

1. Configure file log/report paths:
```toml
[logging]
file = "/var/log/dhi/dhi.log"

[reporting]
output_dir = "/var/log/dhi/reports"
```

2. Verify rotation setup:
```bash
sudo logrotate -d /etc/logrotate.d/dhi
systemctl status logrotate.timer
```

If logrotate is not installed or not running, Dhi logs/reports can grow unbounded. In that case:
- install/enable logrotate, or
- rely on journald retention limits (`SystemMaxUse`, `MaxRetentionSec`) and avoid file append logging until rotation is enabled.

Note for macOS/Windows: only proxy mode is available and currently untested; see [docs/NON_LINUX_PROXY.md](docs/NON_LINUX_PROXY.md).

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
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │                      SECURITY SCANNING                             │     │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │     │
│  │  │  Secrets    │ │    PII      │ │  Prompt     │ │    Tool     │   │     │ 
│  │  │  Detection  │ │  Detection  │ │  Injection  │ │    Risk     │   │     │
│  │  │  (20+ types)│ │  & Redact   │ │  Detection  │ │  Assessment │   │     │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │     │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │     │
│  │  │   Budget    │ │    SSRF     │ │   eBPF SSL  │ │  Jailbreak  │   │     │
│  │  │   Control   │ │  Protection │ │  Intercept  │ │  Detection  │   │     │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                    │                                        │
│                    ┌───────────────┼───────────────┐                        │
│                    │ ✋ BLOCK  🚨 ALERT 📝 LOG   │                        │
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
│     ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                │
│     │ Claude Code  │    │ Copilot CLI  │    │  LangChain   │                │
│     │              │    │              │    │   CrewAI     │                │
│     └──────────────┘    └──────────────┘    └──────────────┘                │
└─────────────────────────────────────────────────────────────────────────────┘
```

**How it works:**
1. **Run Dhi in default mode (eBPF on Linux)** with no agent-side proxy configuration.
2. **Dhi attaches eBPF SSL hooks** and intercepts plaintext traffic at runtime.
3. **Security checks** scan for secrets, PII, prompt injection/jailbreaks, and risky tools.
4. **Policy action** is applied as configured: Block (stop), Alert (notify + allow), or Log (record only).
5. **Telemetry and alerts** are exported to Slack, Prometheus, webhook, or SIEM pipelines.

macOS/Windows note: proxy mode only and currently untested. See [docs/NON_LINUX_PROXY.md](docs/NON_LINUX_PROXY.md).

## Documentation

| Document | Description |
|----------|-------------|
| [Operations Guide](docs/OPERATIONS.md) | **Start here** - Install, start, stop, troubleshoot |
| [User Guide](docs/USER_GUIDE.md) | Consolidated usage, modes, protections, integrations, reporting |
| [CTO Guide](docs/CTO_GUIDE.md) | Executive-ready security narrative for blog/announcement reuse |
| [Testing Guide](docs/TESTING.md) | Manual acceptance test cases for alert/block release validation |
| [Security Guide](docs/SECURITY.md) | Security posture, hardening, and vulnerability reporting |
| [Non-Linux Proxy Note](docs/NON_LINUX_PROXY.md) | macOS/Windows proxy-mode-only note (currently untested) |
| [Comparison](docs/COMPARISON.md) | How Dhi compares to other tools |
| [Branding](docs/BRANDING.md) | Brand and positioning assets |

Contributions are welcome for additional security patterns and framework support; see [Developer Guide](docs/DEVELOPER_GUIDE.md).

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
| `GET /api/agents` | Agent/session fingerprint report (frameworks, sessions, token/tool counters) |

### Session attribution model

Dhi uses a hybrid model:

- **Deterministic identity**: stable `session_id` and agent identity based on process/session signals.
- **Best-effort naming**: `session_name` enrichment from strongest available source.

Session name precedence is:

1. Request payload/header names (`session_name`, `conversation_name`, etc.)
2. Environment variables (`DHI_SESSION_NAME`, `COPILOT_SESSION_NAME`, etc.)
3. Copilot disk metadata (`~/.copilot/session-state/*/workspace.yaml`)
4. tmux session name via tty mapping
5. Fallback: `process@cwd(tty)`

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
