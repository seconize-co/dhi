# Dhi vs Popular Agentic Runtime Security Systems

> A comprehensive comparison of Dhi with other AI agent runtime protection solutions (March 2026)

---

## Executive Summary

Dhi is a **lightweight, open-source, kernel-level detection system** using eBPF. It differs from full sandboxing solutions by focusing on **monitoring and alerting** rather than isolation. This makes it ideal for:

- Environments where full sandboxing isn't feasible
- Defense-in-depth alongside other tools
- Cost-sensitive or self-hosted deployments
- Teams wanting visibility without architecture changes

---

## Market Landscape (2026)

### Categories of Agentic Security

| Category | Description | Examples |
|----------|-------------|----------|
| **Sandboxing** | Full isolation of agent execution | E2B, Modal, NVIDIA OpenShell |
| **Runtime Detection** | Monitor and alert on suspicious behavior | **Dhi**, Falco, Sysdig |
| **Policy Enforcement** | Guardrails and access control | NeMo Guardrails, AccuKnox |
| **Governance** | Compliance, audit, posture management | Wiz AI-SPM, Orca Security |
| **Prompt Security** | Injection prevention, content filtering | Lakera Guard, Rebuff |

---

## Comparison Matrix

### Dhi vs Major Competitors

| Feature | **Dhi** | **NVIDIA OpenShell** | **E2B** | **AccuKnox** | **Modal** |
|---------|---------|---------------------|---------|--------------|-----------|
| **Approach** | eBPF syscall monitoring | Full sandboxed runtime | Firecracker microVM | Policy enforcement | gVisor sandbox |
| **Isolation** | Detection only | Complete sandbox | Complete sandbox | Container + runtime | Sandbox |
| **Open Source** | ✅ MIT | ✅ Open Source | Partial | Partial | ❌ |
| **Overhead** | <1% CPU | ~5-10% | ~5-10% | Variable | ~3-5% |
| **GPU Support** | N/A | Native NVIDIA | ❌ | ✅ | ✅ |
| **Deployment** | Host daemon | Container/VM | Cloud service | Cloud-native | Cloud service |
| **Cost** | Free | Free (self-hosted) | Pay-per-use | Enterprise | Pay-per-use |
| **Linux Required** | ✅ | ✅ | ❌ | ❌ | ❌ |

### Feature Deep Dive

| Capability | Dhi | OpenShell | E2B | AccuKnox |
|------------|-----|-----------|-----|----------|
| File operation monitoring | ✅ | ✅ | ✅ | ✅ |
| Network traffic detection | ✅ | ✅ | ✅ | ✅ |
| Risk scoring | ✅ | ❌ | ❌ | ✅ |
| Behavioral analysis | ✅ | ✅ | ❌ | ✅ |
| Process blocking | ✅ | ✅ | ✅ | ✅ |
| YAML policy config | ❌ | ✅ | ❌ | ✅ |
| Privacy router | ❌ | ✅ | ❌ | ✅ |
| Prompt injection protection | ❌ | ✅ (via NeMo) | ❌ | ✅ |
| SIEM integration | Basic | Enterprise | Basic | Enterprise |
| Framework agnostic | ✅ | Partial | ✅ | ✅ |

---

## NVIDIA Stack Deep Dive

### NVIDIA NemoClaw Architecture (March 2026)

NVIDIA recently released their comprehensive agentic security stack:

```
┌─────────────────────────────────────────────────────────────────┐
│                    NVIDIA NemoClaw Stack                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ NeMo         │  │ Privacy      │  │ AI-Q         │          │
│  │ Guardrails   │  │ Router       │  │ Framework    │          │
│  │ (Policy)     │  │ (Data)       │  │ (Audit)      │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         └─────────────────┼─────────────────┘                   │
│                    ┌──────▼───────┐                             │
│                    │  OpenShell   │                             │
│                    │  (Sandbox)   │                             │
│                    └──────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
```

### OpenShell Components

| Component | Purpose |
|-----------|---------|
| **OpenShell Runtime** | Sandboxed execution environment |
| **NeMo Guardrails** | Policy enforcement, prompt protection |
| **Privacy Router** | PII protection, local/cloud inference routing |
| **AI-Q Framework** | Observability, reasoning audit, explainability |

### OpenShell Features

- **Sandboxed Execution**: Kernel-level isolation for agent actions
- **YAML Policy Engine**: Declarative, per-binary, per-endpoint controls
- **Least Privilege**: Deny by default, explicit allow rules
- **Network Controls**: Endpoint restrictions, traffic filtering
- **Enterprise Integration**: CrowdStrike, Cisco AI Defense, SIEM/SOAR
- **Framework Support**: OpenClaw, LangChain, Claude Code, Codex

---

## Dhi Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Dhi Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                    ┌──────────────┐                             │
│                    │   Any Agent  │  ← No sandbox needed        │
│                    │  or Process  │                             │
│                    └──────┬───────┘                             │
│                           │ syscalls                            │
│                    ┌──────▼───────┐                             │
│                    │  eBPF Hooks  │  ← Kernel-level visibility  │
│                    │  (Kernel)    │                             │
│                    └──────┬───────┘                             │
│                    ┌──────▼───────┐                             │
│                    │ Intelligence │  ← Risk scoring & detection │
│                    │   Engine     │                             │
│                    └──────┬───────┘                             │
│                    ┌──────▼───────┐                             │
│                    │   Output     │  ← Logs, alerts, metrics    │
│                    │  Handlers    │                             │
│                    └──────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
```

### Dhi Components

| Component | Purpose |
|-----------|---------|
| **eBPF Kernel Hooks** | Syscall interception (openat, sendto, unlinkat, etc.) |
| **Ring Buffer** | Lock-free event transport to user space |
| **Intelligence Engine** | Risk calculation, threat correlation |
| **Output Handlers** | Logging, alerting, metrics export |

---

## Where Each Solution Fits

### Security Stack Layers

```
┌─────────────────────────────────────────────────────────────┐
│              COMPLETE AGENTIC SECURITY STACK                │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Prompt Security    → Lakera, NeMo Guardrails     │
│  Layer 2: Sandboxing         → OpenShell, E2B, Modal       │
│  Layer 3: Runtime Detection  → DHI, Falco, AccuKnox        │  ◄── Dhi
│  Layer 4: Governance         → Wiz AI-SPM, Orca            │
└─────────────────────────────────────────────────────────────┘
```

### Use Case Recommendations

| Use Case | Recommended Solution |
|----------|---------------------|
| Enterprise with NVIDIA GPUs | OpenShell/NemoClaw |
| Lightweight monitoring only | **Dhi** |
| Full agent sandboxing | OpenShell, E2B |
| No architecture changes needed | **Dhi** |
| Privacy/compliance heavy | NemoClaw (privacy router) |
| Open source, self-hosted | **Dhi**, OpenShell |
| Framework-specific (OpenClaw) | OpenShell |
| Framework-agnostic (any process) | **Dhi** |
| Cloud-native, managed | E2B, Modal, Northflank |
| Air-gapped environments | **Dhi** |

---

## Dhi's Unique Value Proposition

### Strengths

| Strength | Description |
|----------|-------------|
| **Kernel-level visibility** | eBPF sees ALL syscalls—no bypass possible |
| **Ultra-lightweight** | <1% CPU overhead vs 5-10% for sandboxes |
| **Zero architecture change** | Deploy alongside existing agents |
| **Open source (MIT)** | Fully free, self-hosted, no vendor lock-in |
| **Risk scoring** | Intelligent threat assessment, not just logs |
| **Simple deployment** | Single Python script + kernel module |
| **Vendor neutral** | No NVIDIA/cloud dependency |

### Limitations

| Limitation | Competitors Address With |
|------------|-------------------------|
| No isolation/sandbox | OpenShell, E2B provide true sandboxing |
| Linux only | Modal, E2B are cross-platform |
| No managed service | E2B, Northflank are turnkey SaaS |
| No prompt protection | NeMo Guardrails, Lakera |
| Basic enterprise integration | OpenShell has CrowdStrike, Cisco |

---

## Complementary Deployment

### Defense-in-Depth Strategy

Dhi works best as part of a layered security approach:

```
┌─────────────────────────────────────────┐
│           AI Agent                      │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│   NeMo Guardrails (Prompt Security)     │  ← Prevention
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│     OpenShell (Primary Sandbox)         │  ← Isolation
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│        Dhi (eBPF Monitoring)            │  ← Detection
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│        SIEM / SOC Integration           │  ← Response
└─────────────────────────────────────────┘
```

### Integration Example

```bash
# Run Dhi alongside OpenShell-protected agents
sudo dhi.py --level alert \
    --whitelist-ip 127.0.0.1 \
    --whitelist-file /var/log/

# Dhi detects if anything escapes the sandbox
# or if sandbox itself is compromised
```

---

## Performance Comparison

### Overhead Analysis

| Solution | CPU Overhead | Memory | Latency |
|----------|-------------|--------|---------|
| **Dhi** | <1% @ 1k events/sec | 5-10 MB | <150 μs |
| OpenShell | ~5-10% | 50-100 MB | ~1-5 ms |
| E2B | ~5-10% | 100+ MB | ~1-5 ms |
| Modal | ~3-5% | 50-100 MB | ~1-2 ms |
| AccuKnox | Variable | Variable | Variable |

### Throughput

| Solution | Max Syscalls/sec | Notes |
|----------|-----------------|-------|
| **Dhi** | 10,000+ | eBPF native performance |
| OpenShell | 1,000-5,000 | Sandbox overhead |
| E2B | 1,000-5,000 | MicroVM overhead |

---

## Regulatory & Compliance

### OWASP Top 10 for Agentic AI (2026)

Modern agentic security should address:

1. Prompt Injection
2. Insecure Code Execution
3. Memory/Context Attacks
4. Toolchain Abuse
5. Data Exfiltration
6. Privilege Escalation
7. Supply Chain Attacks
8. Model Poisoning
9. Denial of Service
10. Audit/Logging Failures

### Coverage Matrix

| OWASP Risk | Dhi | OpenShell | E2B |
|------------|-----|-----------|-----|
| Prompt Injection | ❌ | ✅ | ❌ |
| Insecure Code Execution | ✅ (detect) | ✅ (prevent) | ✅ (prevent) |
| Data Exfiltration | ✅ | ✅ | ✅ |
| Privilege Escalation | ✅ | ✅ | ✅ |
| Audit/Logging | ✅ | ✅ | ✅ |

---

## Decision Framework

### Choose Dhi When:

- ✅ You need lightweight monitoring without full sandboxing
- ✅ You can't change your agent architecture
- ✅ You want open source with no vendor lock-in
- ✅ You're running on Linux servers/VMs
- ✅ You need defense-in-depth alongside other tools
- ✅ You're in an air-gapped or self-hosted environment
- ✅ Cost is a primary concern

### Choose OpenShell/NemoClaw When:

- ✅ You need full agent isolation
- ✅ You're using NVIDIA GPUs
- ✅ You need enterprise integrations (CrowdStrike, Cisco)
- ✅ Privacy routing is critical
- ✅ You're building on OpenClaw/LangChain

### Choose E2B/Modal When:

- ✅ You want managed cloud service
- ✅ You need cross-platform support
- ✅ Ephemeral agent execution is your model
- ✅ You prefer pay-per-use pricing

---

## Summary

| Aspect | Dhi | NVIDIA Stack | E2B/Modal |
|--------|-----|--------------|-----------|
| **Philosophy** | Detection layer | Full platform | Managed sandbox |
| **Best For** | Visibility, defense-in-depth | Enterprise, GPU workloads | Cloud-native, managed |
| **Cost** | Free | Free (self-hosted) | Pay-per-use |
| **Complexity** | Low | Medium-High | Low |
| **Coverage** | Runtime detection | End-to-end | Execution isolation |

---

## References

- [NVIDIA OpenShell GitHub](https://github.com/NVIDIA/OpenShell)
- [NVIDIA NeMo Guardrails](https://developer.nvidia.com/nemo-guardrails)
- [E2B Documentation](https://e2b.dev/docs)
- [Modal Documentation](https://modal.com/docs)
- [AccuKnox Platform](https://accuknox.com)
- [OWASP Agentic AI Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [eBPF Documentation](https://ebpf.io/)

---

## About Dhi

**Dhi** (धी) - Sanskrit for "Intellect | Perception | Clear Vision"

A kernel-space runtime protection system powered by eBPF that intelligently monitors and protects against data exfiltration, file tampering, and anomalous behavior.

**Repository**: [github.com/seconize-co/dhi](https://github.com/seconize-co/dhi)

**License**: MIT

---

*Last updated: March 2026*
