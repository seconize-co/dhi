# Dhi vs AI Agent Security Tools (2026)

> Comprehensive comparison of Dhi with guardrails, sandboxes, and runtime security solutions

---

## Executive Summary

**Dhi** is a **runtime security layer** for AI agents that sits between your agents and external services. Unlike sandboxing solutions that isolate code execution, Dhi focuses on **detecting and blocking security threats** in real-time:

- 🔐 Credential/secret leakage detection
- 🛡️ PII exposure prevention
- 💉 Prompt injection blocking
- 💰 Cost/budget enforcement
- 📊 Security observability
- 🔒 **HTTPS traffic interception** (unique capability)

**Key Differentiators**:
1. **eBPF SSL Hooking**: Dhi is the **only open-source tool** that can intercept HTTPS traffic at the kernel level without requiring certificate installation. This means full visibility into encrypted LLM API calls.
2. **Kernel-Level Monitoring**: Combined syscall and SSL/TLS interception in a single package.
3. **Zero Configuration**: Works with any AI tool via proxy or eBPF - no code changes needed.

---

## 🔒 HTTPS Interception: Dhi's Unique Capability

Most security tools can only see HTTP traffic or require MITM certificate installation for HTTPS. Dhi uses **eBPF uprobes** to capture plaintext data directly from SSL library functions:

| Tool | HTTP | HTTPS (Proxy) | HTTPS (eBPF) | No Cert Needed |
|------|------|---------------|--------------|----------------|
| **Dhi** | ✅ | ✅ | ✅ | ✅ |
| NeMo Guardrails | ✅ | ❌ | ❌ | N/A |
| Guardrails AI | ✅ | ❌ | ❌ | N/A |
| LlamaGuard | ✅ | ❌ | ❌ | N/A |
| Rebuff/Lakera | ✅ | ⚠️ (API) | ❌ | N/A |
| mitmproxy | ✅ | ✅ | ❌ | ❌ (needs CA) |
| Falco | ❌ | ❌ | ❌ | N/A |

**How it works:**

```
Your Agent
    │
    │ SSL_write("sk-proj-abc123...")  ← eBPF captures plaintext HERE
    ▼
┌─────────────────┐
│   OpenSSL       │ ← Dhi hooks SSL_read/SSL_write
│   (encrypt)     │
└────────┬────────┘
         │
         │ [Encrypted TLS traffic]
         ▼
    api.openai.com
```

This means Dhi can scan for secrets, PII, and injection attempts **even in HTTPS traffic** without:
- Installing a CA certificate
- Modifying your application
- Running a MITM proxy

---

## Market Landscape (2026)

### Categories of AI Agent Security

| Category | Focus | Examples |
|----------|-------|----------|
| **Guardrails** | LLM input/output filtering | NeMo Guardrails, Guardrails AI, LlamaGuard |
| **Sandboxing** | Code execution isolation | E2B, Modal, Daytona |
| **Runtime Security** | Threat detection & blocking | **Dhi**, Falco, Tracee |
| **Prompt Defense** | Injection/jailbreak prevention | Rebuff, Lakera Guard, Prompt Armor |
| **Observability** | Monitoring & tracing | Langfuse, LangSmith, Helicone |

---

## Detailed Comparisons

### 1. Dhi vs NeMo Guardrails (NVIDIA)

| Aspect | **Dhi** | **NeMo Guardrails** |
|--------|---------|---------------------|
| **Focus** | Runtime security (secrets, PII, costs) | Conversational safety (topics, responses) |
| **Language** | Rust (high performance) | Python + Colang DSL |
| **Detection** | 20+ secret patterns, 12+ PII types | Topic rails, content filtering |
| **Prompt Security** | ✅ Injection + jailbreak detection | ✅ Jailbreak prevention |
| **Cost Control** | ✅ Budget limits per agent | ❌ Not included |
| **Kernel Monitoring** | ✅ eBPF syscall tracking | ❌ Application layer only |
| **Latency** | <5ms overhead | 10-200ms (depends on rails) |
| **Best For** | Security-focused teams | Conversational AI safety |

**When to use NeMo Guardrails**: You need topic control, response safety, and conversational flow management.

**When to use Dhi**: You need to prevent data leaks, enforce budgets, and detect threats at the system level.

---

### 2. Dhi vs Guardrails AI

| Aspect | **Dhi** | **Guardrails AI** |
|--------|---------|-------------------|
| **Focus** | Security threats | Output validation & formatting |
| **Approach** | Block threats in real-time | Validate/retry LLM outputs |
| **Schema Enforcement** | ❌ Not a focus | ✅ Pydantic validation |
| **Secret Detection** | ✅ 20+ patterns | ❌ Not included |
| **PII Detection** | ✅ Auto-redaction | ⚠️ Basic (via validators) |
| **Prompt Injection** | ✅ 30+ attack patterns | ⚠️ Limited |
| **Implementation** | Rust library/daemon | Python decorators |

**When to use Guardrails AI**: You need structured outputs, JSON validation, and retry logic.

**When to use Dhi**: You need security enforcement, not output formatting.

---

### 3. Dhi vs LlamaGuard (Meta)

| Aspect | **Dhi** | **LlamaGuard** |
|--------|---------|----------------|
| **Approach** | Rule-based + patterns | LLM-based classification |
| **Speed** | <5ms | 50-200ms (model inference) |
| **Customization** | Regex patterns, config | Policy prompts |
| **Secret Detection** | ✅ Comprehensive | ❌ Not designed for this |
| **Content Safety** | ⚠️ Basic | ✅ Toxicity, harm, bias |
| **Self-Hosted** | ✅ Single binary | ✅ Open weights |
| **GPU Required** | ❌ No | ✅ Yes (for inference) |

**When to use LlamaGuard**: You need content safety classification (toxicity, harm).

**When to use Dhi**: You need fast, deterministic security checks without GPU overhead.

---

### 4. Dhi vs E2B (Code Sandbox)

| Aspect | **Dhi** | **E2B** |
|--------|---------|---------|
| **Purpose** | Security monitoring | Code execution isolation |
| **Isolation** | Detection + blocking | Firecracker microVM |
| **Use Case** | All AI agents | Code interpreter agents |
| **Deployment** | Self-hosted daemon | Cloud service |
| **Secret Detection** | ✅ Yes | ❌ No |
| **Budget Control** | ✅ Yes | ❌ No |
| **Cold Start** | Instant (always running) | ~150ms per sandbox |
| **Cost** | Free (open source) | Pay-per-use |

**When to use E2B**: Your agent executes untrusted code and needs VM-level isolation.

**When to use Dhi**: You need security monitoring for any agent type, not just code execution.

**Best Practice**: Use both! Dhi for detection, E2B for isolation.

---

### 5. Dhi vs Modal

| Aspect | **Dhi** | **Modal** |
|--------|---------|-----------|
| **Focus** | Security | Infrastructure |
| **Sandboxing** | ❌ Detection only | ✅ gVisor containers |
| **GPU Support** | N/A | ✅ H100, A100 |
| **Secret Detection** | ✅ Yes | ❌ No |
| **Self-Hosted** | ✅ Yes | ❌ Cloud only |
| **Pricing** | Free | Pay-per-use |

**When to use Modal**: You need serverless GPU compute for ML workloads.

**When to use Dhi**: You need security monitoring regardless of where agents run.

---

### 6. Dhi vs Rebuff / Lakera Guard

| Aspect | **Dhi** | **Rebuff / Lakera** |
|--------|---------|---------------------|
| **Focus** | Full runtime security | Prompt injection only |
| **Detection Scope** | Secrets + PII + injections + tools | Prompt attacks only |
| **Budget Control** | ✅ Yes | ❌ No |
| **Tool Monitoring** | ✅ Risk scoring | ❌ No |
| **eBPF/Kernel** | ✅ Yes | ❌ No |
| **Deployment** | Self-hosted | Cloud API |

**When to use Rebuff/Lakera**: You only need prompt injection defense.

**When to use Dhi**: You need comprehensive runtime security.

---

## Feature Comparison Matrix

| Feature | Dhi | NeMo | Guardrails AI | LlamaGuard | E2B | Rebuff |
|---------|-----|------|---------------|------------|-----|--------|
| **HTTPS Interception** | ✅ eBPF | ❌ | ❌ | ❌ | ❌ | ❌ |
| **No Cert Install** | ✅ | N/A | N/A | N/A | N/A | ❌ |
| **Secret Detection** | ✅ 20+ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **PII Detection** | ✅ 12+ | ❌ | ⚠️ | ❌ | ❌ | ❌ |
| **Auto-Redaction** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Prompt Injection** | ✅ | ✅ | ⚠️ | ⚠️ | ❌ | ✅ |
| **Jailbreak Detection** | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **Budget Control** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Tool Risk Scoring** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **MCP Monitoring** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Kernel Monitoring** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Code Sandboxing** | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Content Safety** | ⚠️ | ✅ | ⚠️ | ✅ | ❌ | ❌ |
| **Prometheus Metrics** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Slack Alerts** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Open Source** | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| **Self-Hosted** | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ |

---

## Performance Comparison

| Tool | Latency Overhead | Memory | CPU |
|------|-----------------|--------|-----|
| **Dhi** | <5ms | ~50MB | <1% |
| NeMo Guardrails | 10-200ms | ~500MB | 5-10% |
| LlamaGuard | 50-200ms | ~2GB+ (GPU) | GPU-bound |
| E2B | 150ms cold start | Per-sandbox | Per-sandbox |
| Guardrails AI | 5-50ms | ~200MB | 2-5% |

---

## When to Use What

### Use Dhi When:
- ✅ You need **full HTTPS visibility** without certificate installation
- ✅ You need to prevent credential/secret leaks
- ✅ You need PII detection and redaction
- ✅ You need budget/cost controls per agent
- ✅ You want kernel-level visibility (Linux)
- ✅ You need tool call risk assessment
- ✅ You want self-hosted, open-source solution
- ✅ You need Prometheus metrics for dashboards
- ✅ You're using Claude Code, Copilot CLI, or other AI tools with HTTPS APIs

### Use NeMo Guardrails When:
- ✅ You need conversational topic control
- ✅ You need response quality enforcement
- ✅ You're building chatbots with strict policies

### Use E2B/Modal When:
- ✅ Your agents execute untrusted code
- ✅ You need VM/container-level isolation
- ✅ You're building code interpreter features

### Use LlamaGuard When:
- ✅ You need content safety classification
- ✅ You have GPU resources available
- ✅ You need toxicity/harm detection

---

## Recommended Architecture

For production AI agent deployments, use **defense in depth**:

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR AI AGENTS                           │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: DHI RUNTIME SECURITY                              │
│  • HTTPS interception   • Secret detection                  │
│  • PII protection       • Budget enforcement                │
│  • Tool risk scoring    • Prompt injection                  │
│  • Alerting & metrics   • eBPF kernel monitoring            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  LAYER 2: GUARDRAILS (Optional)                             │
│  • NeMo Guardrails for topic control                        │
│  • LlamaGuard for content safety                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  LAYER 3: SANDBOX (For code execution)                      │
│  • E2B or Modal for untrusted code                          │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                 EXTERNAL SERVICES                           │
│        OpenAI  •  Anthropic  •  Tools  •  APIs              │
└─────────────────────────────────────────────────────────────┘
```

---

## Summary

| Tool | Best For | Complements Dhi? |
|------|----------|------------------|
| **NeMo Guardrails** | Conversational safety | ✅ Yes |
| **Guardrails AI** | Output validation | ✅ Yes |
| **LlamaGuard** | Content classification | ✅ Yes |
| **E2B** | Code sandboxing | ✅ Yes |
| **Modal** | GPU compute | ✅ Yes |
| **Rebuff** | Prompt injection | ⚠️ Overlap |

**Dhi's Unique Capabilities**:
1. **eBPF SSL Hooking** - Only tool that intercepts HTTPS without certificates
2. **Kernel-Level Monitoring** - Syscalls + SSL combined
3. **Zero-Config Protection** - Works with any AI tool via proxy or eBPF

**Dhi fills a unique gap**: runtime security monitoring that no other tool provides comprehensively. Use it as your foundation, add other tools as needed.

---

*Last updated: March 2026*
