# Dhi User Guide

This guide consolidates end-user product usage previously spread across integration, feature, and CTO-facing docs.

For day-2 operations, see [OPERATIONS.md](OPERATIONS.md).
For validation and release readiness, see [TESTING.md](TESTING.md).
For security model and hardening posture, see [SECURITY.md](SECURITY.md).

---

## 1. Core Use Cases

Dhi addresses six primary runtime security concerns:
1. Credential leakage prevention
2. PII exfiltration prevention
3. Cost control and budget enforcement
4. Dangerous tool call control
5. Prompt injection/jailbreak detection
6. Observability for agent activity

---

## 2. Modes and Platform Fit

| Mode | Best platform | Visibility | Recommended use |
|------|---------------|------------|-----------------|
| eBPF mode | Linux | Full SSL plaintext at runtime | Primary production mode |
| Proxy mode | macOS/Windows fallback | Hostname-level only for HTTPS | Compatibility and basic controls |

Production recommendation:
- Run eBPF mode as primary on Linux.
- Run one mode at a time unless you have a specific, documented reason.

---

## 3. Quick Start

### Linux eBPF mode (primary)

```bash
cargo build --release
cd bpf
clang -O2 -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o
sudo mkdir -p /usr/share/dhi
sudo cp dhi_ssl.bpf.o /usr/share/dhi/
cd ..

sudo ./target/release/dhi --level alert
# or
sudo ./target/release/dhi --level block --ebpf-block-action term
```

### Proxy mode (fallback)

```bash
./target/release/dhi proxy --port 18080 --block-secrets --block-pii
export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
```

---

## 4. Key Protections

### Secrets and credentials
- Detects common key/token types (OpenAI, AWS, GitHub, Stripe, private keys, JWT patterns).
- Block mode actively prevents risky egress.

### PII protection
- Detects sensitive personal data (SSN, card-like patterns, phones, emails, addresses).
- Supports redaction/block workflows depending on mode and policy.

### Prompt attack detection
- Detects prompt injection, jailbreak, and prompt extraction patterns.

### Tool risk control
- Risk-scores tool calls and flags/blocks high-risk patterns.

### Budget controls
- Tracks usage and cost signals and can enforce limits.

### Agent observability
- Tracks calls, events, and exposure through API stats and Prometheus metrics.

---

## 5. Agent and Framework Coverage

Dhi is provider/framework agnostic at runtime and supports common coding assistants and agent stacks, including:
- Claude Code
- GitHub Copilot CLI
- LangChain/CrewAI style toolchains
- SDK-driven OpenAI/Anthropic workflows

---

## 6. Reporting and Metrics

### Metrics endpoints
- `GET /metrics`
- `GET /health`
- `GET /ready`
- `GET /api/stats`
- `GET /api/agents`

### Agent/session report fields (`/api/agents`)

The agents report now includes runtime usage counters at multiple levels:

- Report-level: `total_tokens`, `total_tool_calls`
- Agent-level: `total_tokens`, `total_tool_calls`
- Session-level: `total_tokens`, `total_tool_calls`, `session_name`

For multi-terminal Copilot runs, sessions are separated by deterministic process-session IDs (e.g. `copilot-process:<pid>`), with `session_name` populated via best-effort enrichment.

Runtime extraction details:

- `RUN-*` marker extraction is boundary-aware and resilient to fragmented buffer capture.
- Token extraction works with full JSON payloads and SSE `data:` JSON lines.
- Tool extraction covers `tool_calls`, `function_call`, `tools`, and `type:"tool_use"` patterns.
- Session token/tool usage is attributed only to sessions detected on that request.

### Reporting output
- Reporting directory is configurable in `dhi.toml` under `[reporting].output_dir`.
- Typical paths:
- `/tmp/log/dhi/reports` for dev/test
- `/var/log/dhi/reports` for hardened production hosts
- Choose one log/report root per environment (dev/test or production), not both.

See sample output formats:
- `examples/sample-report-daily.json`
- `examples/sample-report-agents.json`

---

## 7. Alerting (Slack/Webhook/Email)

Alert transports are configurable under `[alerting]`.
Alert payloads include traceability metadata for investigation:
- `correlation_id`
- `event_type`
- `destination` and `path` (when request context is available)
- `action_taken` (`ALERTED`/`BLOCKED`/`ALLOWED`)
- `session_id` and optional `session_name` (when session extraction succeeds)
- `process_name`/`pid` (when process context is available)

For runtime/session investigation, continue to use `GET /api/agents` plus monitor logs; there is currently no dedicated `/api/alerts` endpoint.

Recommended rollout:
1. Start in alert mode.
2. Tune false positives and trusted paths/hosts.
3. Move to block mode once confidence is high.

---

## 8. Testing and Validation

Use these harnesses:
- `scripts/security-e2e.sh` for deterministic regression and endpoint checks
- `scripts/copilot-cli-e2e.sh` for Copilot CLI/eBPF scenario validation
- `scripts/reporting-e2e.sh` for reporting schema/artifact checks (Slack excluded)

Full acceptance flow is defined in [TESTING.md](TESTING.md).

---

## 9. Configuration Anchors

Primary configuration sources:
- `dhi.toml.example`
- `.env.example`

These files are normative for key names/defaults; docs should follow them.
