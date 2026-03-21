# Dhi for CTOs: Agentic AI Risk & Efficiency

> What every CTO needs to know before deploying AI agents in production

---

## The CTO's Agentic AI Concerns

```
┌─────────────────────────────────────────────────────────────────┐
│                    CTO'S NIGHTMARE SCENARIOS                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  😱 "Our AI agent just leaked API keys to a public endpoint"   │
│                                                                 │
│  😱 "The agent uploaded 50,000 customer records somewhere"     │
│                                                                 │
│  😱 "We're burning $10K/day on redundant LLM calls"            │
│                                                                 │
│  😱 "I have no idea what tools our agents are actually using"  │
│                                                                 │
│  😱 "The agent keeps calling the same API in an infinite loop" │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Dhi solves all of these.**

---

## Use Case 1: Credential & Secret Protection

### The Problem
AI agents have access to environment variables, config files, and memory that may contain:
- API keys (OpenAI, AWS, Stripe, etc.)
- Database credentials
- OAuth tokens
- Private keys
- Internal service passwords

### How Dhi Protects

```python
# Dhi automatically detects credentials in:
# ✓ Prompts being sent to LLMs
# ✓ Tool call parameters
# ✓ File access patterns
# ✓ Network payloads

# Example detection:
[ALERT] Sensitive data in prompt: API key pattern detected
        Agent: data-processor-01
        Pattern: sk-proj-xxxxx (OpenAI key)
        Action: BLOCKED (block mode) / LOGGED (alert mode)

[ALERT] Credential file access
        Agent: research-agent
        File: /home/app/.env
        Action: Alert sent to #security-alerts
```

### Detection Patterns

| Pattern | Example | Risk |
|---------|---------|------|
| OpenAI API Key | `sk-proj-...` | Critical |
| AWS Access Key | `AKIA...` | Critical |
| Private Key | `-----BEGIN RSA PRIVATE KEY-----` | Critical |
| Generic Secret | `password=`, `secret=`, `token=` | High |
| Database URL | `postgresql://user:pass@host` | Critical |
| JWT Token | `eyJ...` (long base64) | High |

### Configuration

```toml
[secrets_detection]
enabled = true
action = "block"  # or "alert"

# Custom patterns
custom_patterns = [
    "INTERNAL_SERVICE_KEY_\\w+",
    "my-company-secret-\\d+",
]

# Allowlist (won't alert on these)
allowlist = [
    "sk-test-*",  # Test keys OK
]
```

---

## Use Case 2: Customer Data Protection

### The Problem
Agents processing customer data might accidentally:
- Include PII in prompts sent to external LLMs
- Upload customer records to wrong endpoints
- Log sensitive data to observability tools
- Share data across tenant boundaries

### How Dhi Protects

```python
# Dhi scans for PII in all agent communications:

[ALERT] PII detected in LLM request
        Agent: customer-support-bot
        Data types: email (3), phone (2), SSN (1)
        Destination: api.openai.com
        Action: Request blocked, PII redacted

[ALERT] Bulk data transmission detected
        Agent: analytics-agent  
        Records: ~50,000 (estimated from payload size)
        Destination: 34.123.45.67:443 (unknown)
        Action: BLOCKED - exceeded data egress threshold
```

### PII Detection

| Data Type | Pattern | Auto-Action |
|-----------|---------|-------------|
| Email | `*@*.com` | Redact |
| Phone | `XXX-XXX-XXXX` | Redact |
| SSN | `XXX-XX-XXXX` | Block |
| Credit Card | `4XXX-XXXX-...` | Block |
| Address | Street patterns | Warn |
| Name + DOB | Combined PII | Warn |

### Data Egress Controls

```toml
[data_protection]
# Maximum bytes per request to external APIs
max_request_size_bytes = 1048576  # 1MB

# Maximum records (estimated) per request
max_records_per_request = 100

# Allowed destinations for large transfers
allowed_data_destinations = [
    "*.your-company.com",
    "s3.amazonaws.com/your-bucket",
]

# Block all others for large transfers
block_unknown_large_transfers = true
```

---

## Use Case 3: Prompt & Tool Efficiency Analysis

### The Problem
Without visibility, you're wasting money on:
- Redundant prompts (asking the same thing repeatedly)
- Inefficient tool usage (5 API calls when 1 would do)
- Token bloat (huge context windows when summarization would work)
- Repeated failures (same error, same retry, same failure)

### How Dhi Optimizes

```python
# Dhi tracks patterns and suggests optimizations:

═══════════════════════════════════════════════════════════════════
  EFFICIENCY REPORT - Last 24 Hours
═══════════════════════════════════════════════════════════════════

  💸 COST ANALYSIS
     Total spend:        $847.32
     Potential savings:  $312.45 (37%)

  🔄 REDUNDANT PATTERNS DETECTED

  1. Duplicate Prompts (127 occurrences)
     Pattern: "Summarize the following document..."
     Agent: document-processor
     Suggestion: Cache summaries, check before re-processing
     Potential savings: $89.50

  2. Repeated Tool Failures (43 occurrences)
     Tool: database_query
     Error: "Connection timeout"
     Agent: data-analyst
     Suggestion: Add retry backoff, check DB health before query
     Potential savings: $12.30

  3. Oversized Context (89 occurrences)
     Average context: 45,000 tokens
     Used context: ~8,000 tokens (18%)
     Agent: research-assistant
     Suggestion: Implement context pruning, use summaries
     Potential savings: $156.80

  4. Tool Call Loops (12 occurrences)
     Pattern: web_search → web_search → web_search (same query)
     Agent: research-bot
     Max iterations: 47 (!)
     Suggestion: Add loop detection, cache results
     Potential savings: $53.85

═══════════════════════════════════════════════════════════════════
```

### Inefficiency Detection

| Pattern | Detection | Recommendation |
|---------|-----------|----------------|
| Same prompt 3+ times | Hash matching | Add caching layer |
| Tool loop (same params) | Call sequence analysis | Add loop breaker |
| Large context, small output | Token ratio analysis | Use summarization |
| Failed retries | Error pattern matching | Fix root cause |
| Unused tool results | Result → next prompt analysis | Remove unnecessary calls |

### Configuration

```toml
[efficiency]
enabled = true

# Alert on repeated identical prompts
duplicate_prompt_threshold = 3

# Alert on tool call loops
tool_loop_detection = true
max_identical_tool_calls = 5

# Context efficiency warnings
context_efficiency_threshold = 0.3  # Alert if <30% of context is used

# Cost alerts
daily_budget_usd = 500
alert_at_percentage = 80  # Alert at 80% of budget
```

---

## Use Case 4: Tool Call Visibility & Governance

### The Problem
CTOs need to know:
- What tools are agents actually using?
- Are they accessing systems they shouldn't?
- Who approved this tool access?
- What's the blast radius if this agent goes rogue?

### Dhi's Visibility Dashboard

```
═══════════════════════════════════════════════════════════════════
  TOOL USAGE REPORT - All Agents
═══════════════════════════════════════════════════════════════════

  TOOL INVENTORY (Active in last 24h)
  ┌─────────────────────────────────────────────────────────────┐
  │ Tool Name          │ Calls  │ Agents │ Risk   │ Status     │
  ├─────────────────────────────────────────────────────────────┤
  │ web_search         │ 12,847 │ 8      │ Low    │ ✓ Approved │
  │ database_query     │ 5,432  │ 3      │ Medium │ ✓ Approved │
  │ send_email         │ 234    │ 2      │ Medium │ ✓ Approved │
  │ file_write         │ 89     │ 1      │ High   │ ⚠ Review   │
  │ shell_execute      │ 12     │ 1      │ Critical│ ✗ Blocked │
  │ http_request       │ 2,341  │ 5      │ Medium │ ✓ Approved │
  └─────────────────────────────────────────────────────────────┘

  UNAPPROVED TOOL ATTEMPTS (Blocked)
  ┌─────────────────────────────────────────────────────────────┐
  │ Time       │ Agent              │ Tool         │ Params     │
  ├─────────────────────────────────────────────────────────────┤
  │ 14:32:01   │ research-agent     │ shell_exec   │ rm -rf /tmp│
  │ 14:28:45   │ data-processor     │ ftp_upload   │ external IP│
  │ 13:15:22   │ customer-bot       │ sql_execute  │ DROP TABLE │
  └─────────────────────────────────────────────────────────────┘

  TOP TOOL CONSUMERS (By Cost)
  1. research-agent:     $234.50 (web_search: 67%)
  2. data-processor:     $189.20 (database_query: 89%)
  3. customer-support:   $145.80 (send_email: 45%)

═══════════════════════════════════════════════════════════════════
```

### Tool Governance

```toml
[tool_governance]
# Default policy: deny all, allow specific
default_policy = "deny"

# Approved tools (with risk levels)
[tool_governance.approved]
web_search = { risk = "low", requires_approval = false }
database_query = { risk = "medium", requires_approval = false }
send_email = { risk = "medium", requires_approval = true, approvers = ["security-team"] }
file_write = { risk = "high", requires_approval = true, approvers = ["cto", "security-team"] }

# Explicitly denied tools
[tool_governance.denied]
shell_execute = "Never allow shell access"
ftp_upload = "Use approved file transfer only"
sql_execute = "Use parameterized queries via database_query"

# Per-agent overrides
[tool_governance.agents.trusted-internal-agent]
additional_tools = ["file_write", "http_request"]
```

---

## Use Case 5: API Call Monitoring & Cost Control

### The Problem
- LLM API costs can spiral out of control
- No visibility into which agents are expensive
- Can't attribute costs to business functions
- Surprise bills at end of month

### Dhi's Cost Control

```
═══════════════════════════════════════════════════════════════════
  LLM API COST DASHBOARD
═══════════════════════════════════════════════════════════════════

  TODAY'S SPEND
  ┌─────────────────────────────────────────────────────────────┐
  │ ████████████████████░░░░░░░░░░░░░░░░░░░░  $423 / $500 (85%) │
  └─────────────────────────────────────────────────────────────┘
  ⚠️  Warning: Approaching daily budget limit

  BY PROVIDER
  ┌─────────────────────────────────────────────────────────────┐
  │ Provider    │ Calls  │ Tokens     │ Cost    │ Avg/Call     │
  ├─────────────────────────────────────────────────────────────┤
  │ OpenAI      │ 2,341  │ 4.5M       │ $312.45 │ $0.133       │
  │ Anthropic   │ 892    │ 1.2M       │ $98.20  │ $0.110       │
  │ Google      │ 234    │ 0.3M       │ $12.35  │ $0.053       │
  └─────────────────────────────────────────────────────────────┘

  BY AGENT
  ┌─────────────────────────────────────────────────────────────┐
  │ Agent                │ Calls │ Cost    │ Efficiency │ Trend │
  ├─────────────────────────────────────────────────────────────┤
  │ research-assistant   │ 1,234 │ $234.50 │ 72%        │ ↑ 15% │
  │ customer-support     │ 892   │ $89.20  │ 91%        │ ↓ 5%  │
  │ data-analyst         │ 456   │ $67.30  │ 45%        │ ↑ 23% │
  │ document-processor   │ 234   │ $32.00  │ 88%        │ → 0%  │
  └─────────────────────────────────────────────────────────────┘

  ⚠️  COST ANOMALIES
  • research-assistant: 340% above normal (investigating...)
  • data-analyst: Efficiency dropped from 78% to 45%

═══════════════════════════════════════════════════════════════════
```

### Budget Controls

```toml
[budget]
# Global limits
daily_limit_usd = 500
monthly_limit_usd = 10000
alert_threshold_percent = 80

# Per-agent limits
[budget.agents]
research-assistant = { daily = 100, monthly = 2000 }
customer-support = { daily = 50, monthly = 1000 }
data-analyst = { daily = 75, monthly = 1500 }

# Actions when budget exceeded
on_limit_reached = "block"  # or "alert", "throttle"

# Cost anomaly detection
anomaly_detection = true
anomaly_threshold_percent = 200  # Alert if 2x normal
```

---

## Use Case 6: Loop & Infinite Recursion Detection

### The Problem
Agents can get stuck in loops:
- Retrying failed operations indefinitely
- Calling the same tool with same parameters
- Recursive agent spawning
- Infinite conversation loops

### Dhi's Loop Detection

```python
[ALERT] Tool call loop detected
        Agent: research-bot
        Tool: web_search
        Pattern: Same query repeated 15 times
        Query: "latest news about AI"
        Action: Loop broken, agent notified

[ALERT] Agent spawn loop detected
        Parent: orchestrator-agent
        Pattern: Spawning child agents exponentially
        Children spawned: 64 in 30 seconds
        Action: Spawn blocked, alert sent

[ALERT] Conversation loop detected
        Agent: customer-support
        Pattern: Same response generated 5 times
        Response hash: a3f2b1c4...
        Action: Conversation terminated
```

### Loop Prevention

```toml
[loop_detection]
enabled = true

# Tool call limits
max_identical_tool_calls = 5
tool_call_window_seconds = 60

# Agent spawn limits
max_child_agents = 10
max_spawn_rate_per_minute = 5

# Conversation limits
max_identical_responses = 3
max_conversation_turns = 100

# Actions
on_loop_detected = "break"  # or "alert", "throttle"
notify_channels = ["#agent-alerts", "oncall@company.com"]
```

---

## Implementation: Quick Start for CTOs

### 1. Deploy in Alert Mode (Week 1)

```bash
# Start with visibility only - no blocking
sudo dhi --level alert \
    --config /etc/dhi/production.toml

# Review logs
dhi dashboard
```

### 2. Review & Tune (Week 2)

```bash
# Check what's being flagged
dhi report --last 7d

# Adjust thresholds based on your patterns
dhi config set efficiency.duplicate_prompt_threshold 5
```

### 3. Enable Blocking (Week 3+)

```bash
# Enable blocking for high-confidence rules
sudo dhi --level block \
    --block-rules "credential_leak,pii_exposure,budget_exceeded"
```

### 4. Integrate with Your Stack

```python
# Slack alerts
dhi integrate slack --webhook $SLACK_WEBHOOK

# Prometheus metrics
dhi integrate prometheus --port 9090

# SIEM export
dhi integrate splunk --hec-url $SPLUNK_HEC
```

---

## ROI Calculator

| Risk | Without Dhi | With Dhi | Savings |
|------|-------------|----------|---------|
| Credential leak incident | $500K+ (breach) | $0 (prevented) | $500K |
| Customer data exposure | $1M+ (GDPR fine) | $0 (blocked) | $1M |
| LLM cost overrun | $50K/month waste | $15K/month | $420K/year |
| Agent downtime (loops) | 10h/month | <1h/month | 90% reduction |
| Security audit prep | 2 weeks | 2 days | 80% time saved |

---

## Summary: What CTOs Get

| Concern | Dhi Solution |
|---------|--------------|
| **Credentials stolen** | Auto-detect & block secrets in prompts/tools |
| **Customer data leaked** | PII detection, egress controls |
| **Cost spiral** | Budget limits, anomaly detection |
| **No visibility** | Full tool/API dashboard |
| **Inefficient prompts** | Duplicate detection, optimization hints |
| **Agent loops** | Automatic loop breaking |
| **Compliance audit** | Complete audit trail |

---

## Get Started

```bash
# Install
cargo install dhi

# Configure
dhi init --profile cto

# Deploy
sudo dhi --level alert

# Dashboard
dhi dashboard
```

**Questions?** security@seconize.co

---

*Dhi - धी - Intellect. Perception. Protection.*
