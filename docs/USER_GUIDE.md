# Dhi User Guide (Features and Controls)

This guide is focused on **what Dhi does at runtime**, what each feature means, and how to control behavior using config toggles and use-case IDs.

For deployment/runbook topics, see `OPERATIONS.md`.
For test procedures and acceptance coverage, see `TESTING.md`.

---

## 1. Core Runtime Features

### 1.1 Secrets detection and blocking

- Detects high-risk credentials in requests/responses (API keys, tokens, private keys, JWT-like material).
- In `alert` mode: emits alerts.
- In `block` mode: can actively block based on toggles.

Use-case IDs:
- `sze.dhi.secrets.uc01.detect`
- `sze.dhi.secrets.uc02.block`

### 1.2 PII detection and blocking

- Detects PII indicators (email/phone/SSN/card-like patterns, etc.).
- Can alert-only or block depending on protection mode and toggles.

Use-case IDs:
- `sze.dhi.pii.uc01.detect`
- `sze.dhi.pii.uc02.block`

### 1.3 Prompt attack detection

- Detects prompt injection/jailbreak style payloads.
- Emits enriched runtime alerts and can block in configured paths.

Use-case IDs:
- `sze.dhi.prompt.uc01.detect`
- `sze.dhi.prompt.uc02.block`
- `sze.dhi.prompt.uc03.jailbreak_detect`

### 1.4 SSRF guardrails (proxy path)

- Identifies suspicious/private/internal destinations in CONNECT and request routing.
- Supports detect vs block controls.

Use-case IDs:
- `sze.dhi.ssrf.uc01.detect`
- `sze.dhi.ssrf.uc02.block`

### 1.5 Tool risk monitoring and blocking

- Scores tool invocations for risk and flags dangerous patterns.
- In blocking posture, high-risk tool use can be denied.

Use-case IDs:
- `sze.dhi.tools.uc01.detect`
- `sze.dhi.tools.uc02.block`

### 1.6 Budget controls

- Tracks token/cost spend and raises warning/exceeded signals.
- Supports enforcement behavior when limits are crossed.

Use-case IDs:
- `sze.dhi.budget.uc01.detect`
- `sze.dhi.budget.uc02.block`

### 1.7 Alerting and traceability

- Sends alerts via local JSONL log, Slack webhook, and/or generic webhook.
- Adds correlation/session/process/destination/action metadata for investigations.

Use-case IDs:
- `sze.dhi.alerts.uc01.dispatch`
- `sze.dhi.alerts.uc02.traceability`

### 1.8 Metrics and runtime observability

- Exposes runtime and agent/session counters for monitoring and troubleshooting.

Use-case IDs:
- `sze.dhi.metrics.uc01.observe`

### 1.9 Trusted-host allow behavior

- Supports trusted-host controls to reduce false positives on known-safe paths.

Use-case IDs:
- `sze.dhi.auth.uc01.trusted-host-allow`

---

## 2. Enable/Disable Behavior with `[checks]`

Dhi supports hybrid toggles:

- **Type-level toggles** for broad behavior.
- **Use-case overrides** for precise per-ID control.

Configuration section:

```toml
[checks]
detect_secrets = true
block_secrets = true
detect_pii = true
block_pii = false
detect_prompt_injection = true
block_prompt_injection = true
detect_ssrf = true
block_ssrf = true

use_case_overrides = { "sze.dhi.secrets.uc02.block" = false, "sze.dhi.ssrf.uc02.block" = true }
```

### 2.1 How precedence works

1. Type-level flag sets default behavior.
2. If `use_case_overrides` includes that exact use-case ID, override wins.

Example:
- `block_secrets = true`
- `use_case_overrides["sze.dhi.secrets.uc02.block"] = false`
- Result: secrets can still be detected, but block action for that use case is disabled.

### 2.2 Practical toggle patterns

- **Detect-only rollout**: keep `detect_* = true`, set `block_* = false`.
- **Selective block**: enable all block toggles, then disable specific use-case IDs that are noisy.
- **Targeted hardening**: keep coarse blocks off, enable only key per-use-case blocks through overrides.

---

## 3. Alert Details and Enrichment

Every emitted alert includes base fields:

- `severity`
- `title`
- `message`
- `event_type`
- `timestamp`
- optional `agent_id`

Enrichment metadata (when available):

- `use_case_id`
- `correlation_id`
- `session_id`, optional `session_name`
- `process_name`, `pid`
- `destination`, `path`
- `action_taken` (`ALERTED`, `BLOCKED`, `ALLOWED`)
- `risk_score`

### 3.1 Transport behavior

- **Local log** (`alert_log_path`): append-only JSONL records of full alert payload.
- **Slack webhook**: metadata is sent as attachment fields.
- **Generic webhook**: full alert JSON (including metadata) is posted.

---

## 4. Feature-to-ID Reference

- Secrets: `sze.dhi.secrets.uc01.detect`, `sze.dhi.secrets.uc02.block`
- PII: `sze.dhi.pii.uc01.detect`, `sze.dhi.pii.uc02.block`
- Prompt security: `sze.dhi.prompt.uc01.detect`, `sze.dhi.prompt.uc02.block`, `sze.dhi.prompt.uc03.jailbreak_detect`
- SSRF: `sze.dhi.ssrf.uc01.detect`, `sze.dhi.ssrf.uc02.block`
- Tool risk: `sze.dhi.tools.uc01.detect`, `sze.dhi.tools.uc02.block`
- Budget: `sze.dhi.budget.uc01.detect`, `sze.dhi.budget.uc02.block`
- Alerting: `sze.dhi.alerts.uc01.dispatch`, `sze.dhi.alerts.uc02.traceability`
- Metrics: `sze.dhi.metrics.uc01.observe`
- Trusted-host behavior: `sze.dhi.auth.uc01.trusted-host-allow`

---

## 5. Recommended Usage Strategy

1. Start with detect/alert posture.
2. Review enriched alerts and tune noisy use-case IDs with overrides.
3. Enable block behavior incrementally for mature use cases.
4. Keep alert traceability fields (`use_case_id`, `correlation_id`, `session_id`) mandatory in triage workflow.

---

## 6. Framework Support Model

Dhi’s core protection controls are **framework-agnostic**:

- secrets/PII/prompt/tool-risk detection
- policy actions (log/alert/block)
- alert transport and enrichment

These protections apply at runtime traffic/process layers, not by framework plugin.

### 6.1 What is framework-specific

Framework-specific logic is mainly used for **classification and enrichment**:

- framework identity in `/api/agents` (for example, Copilot CLI, Claude Code, LangChain)
- session naming/context hints
- additional fingerprinting metadata

If a framework is unrecognized, Dhi still protects traffic; it may appear as `Unknown` until fingerprint rules are added.

### 6.2 Currently tested/observed frameworks

- GitHub Copilot CLI
- Claude Code
- LangChain-style workflows
- SDK-driven OpenAI/Anthropic traffic paths

For adding a new framework fingerprint, see `DEVELOPER_GUIDE.md` and `FRAMEWORK_ONBOARDING_GUIDE.md`.
