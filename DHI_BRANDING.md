# DHI - Runtime Intelligence & Protection System

## Project Overview

**Dhi** (धी) - Sanskrit for "Intellect" / "Perception" / "Clear Vision"

A kernel-space runtime protection system for AI agents, powered by intelligent eBPF monitoring.

```
     दिव्य बुद्धि (Supreme Intellect)
           ↓
    ╔════════════════╗
    ║      DHI       ║  The Intelligent Guardian
    ║   Runtime      ║  Sees What Others Cannot
    ║  Protection    ║  Ancient Wisdom, Modern Security
    ╚════════════════╝
           ↓
    Protects Against:
    • Data Exfiltration
    • File Tampering
    • Unauthorized Access
```

---

## What is Dhi?

**Dhi** is a lightweight, kernel-space runtime protection system that uses eBPF (Berkeley Packet Filter) to intelligently monitor and protect against:

- **Data Exfiltration** - Detects unauthorized data transmission by agents
- **File Modifications** - Identifies tampering with critical files
- **Anomalous Behavior** - Recognizes suspicious activity patterns

**Why "Dhi"?**
- Sanskrit root meaning "Intellect" / "Perception"
- Vedic term for clear vision and discernment
- Single syllable - global appeal
- Perfect for an intelligent security system

---

## Core Features

### 🔍 Intelligent Detection
- Real-time syscall monitoring (kernel-level)
- Behavioral analysis & risk scoring
- Pattern recognition for threat detection
- Zero-overhead filtering

### 🛡️ Multi-Layer Protection
- **LOG** mode: Observe all activity
- **ALERT** mode: Flag suspicious behavior
- **BLOCK** mode: Prevent threats in real-time

### 📊 Comprehensive Monitoring
- Network transmission tracking
- File operation monitoring
- Permission change detection
- Process context correlation

### ⚡ High Performance
- <1% CPU overhead at 1k events/sec
- Lock-free ring buffer design
- Minimal memory footprint (5-10MB)
- Scales to 10k+ syscalls/sec

---

## Quick Start

### Installation
```bash
# Prerequisites
sudo apt-get install -y linux-headers-$(uname -r) clang llvm libelf-dev
pip3 install bcc

# Run Dhi
sudo python3 dhi.py --level alert
```

### Protection Levels
```bash
# Log mode (observe only)
sudo dhi.py --level log

# Alert mode (detect & warn)
sudo dhi.py --level alert

# Block mode (enforce protection)
sudo dhi.py --level block
```

### Configuration
```bash
# With whitelisting
sudo dhi.py --level alert \
    --whitelist-ip 10.0.0.0 \
    --whitelist-file /var/log/

# Production deployment
sudo systemctl start dhi
sudo systemctl status dhi
```

---

## Architecture

```
┌─────────────────────────────────────┐
│   User Applications & AI Agents     │
└────────────┬────────────────────────┘
             │ System Calls
┌────────────▼────────────────────────┐
│      Kernel Space (eBPF)            │
│  ┌─────────────────────────────┐   │
│  │ Syscall Hooks:              │   │
│  │ • openat  • unlinkat        │   │
│  │ • sendto  • fchmodat        │   │
│  │ • write   • renameat2       │   │
│  └─────────────────────────────┘   │
│                                     │
│  ┌─────────────────────────────┐   │
│  │ Ring Buffer (Real-time)     │   │
│  │ Events Flow to User Space   │   │
│  └─────────────────────────────┘   │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│    User Space (Python/Dhi)          │
│  ┌─────────────────────────────┐   │
│  │ Intelligence Engine:        │   │
│  │ • Event parsing             │   │
│  │ • Risk calculation          │   │
│  │ • Threat detection          │   │
│  │ • Policy enforcement        │   │
│  └─────────────────────────────┘   │
│                                     │
│  ┌─────────────────────────────┐   │
│  │ Output Handlers:            │   │
│  │ • Logging (syslog)          │   │
│  │ • Alerting (Slack, Email)   │   │
│  │ • Metrics (Prometheus)      │   │
│  │ • SIEM integration          │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

---

## What Dhi Detects

### 1. Data Exfiltration Attempts
```
Threat:     Agent sends database to external server
Detection:  High-volume network transmission to non-whitelisted IP
Response:   Alert or block based on mode

Risk Signals:
├─ Single send > 1MB         → Risk +15
├─ Total bytes > 10MB        → Risk +50
├─ Suspicious port (4444)    → Risk +20
└─ Multiple destinations     → Risk +30
```

### 2. File Tampering
```
Threat:     Agent deletes system files
Detection:  unlinkat() syscall on /etc/, /root/, /.ssh/
Response:   Immediate alert + optionally block

Risk Signals:
├─ Delete /etc/passwd        → Risk +40
├─ Delete /root/.ssh/        → Risk +50
├─ Rapid deletes (>10/sec)   → Risk +25
└─ Permission changes (777)  → Risk +20
```

### 3. Privilege Escalation Attempts
```
Threat:     Agent modifies SUID binaries
Detection:  fchmodat() with mode 0o777
Response:   Alert + restore original permissions

Risk Signals:
├─ chmod 777 on system file  → Risk +25
├─ chown to different UID    → Risk +15
└─ Multiple chmod attempts   → Risk +20
```

### 4. Behavioral Anomalies
```
Threat:     Unusual activity pattern
Detection:  Statistical deviation from baseline
Response:   Alert for human review

Risk Signals:
├─ 100x normal network traffic → Anomaly
├─ Unusual file access patterns → Anomaly
└─ Rapid syscall sequences     → Anomaly
```

---

## Risk Scoring

Dhi calculates a **Risk Score (0-100)** based on detected signals:

```
Risk Calculation:
┌─────────────────────────────────┐
│ Exfiltration Volume (0-50 pts)  │
│ └─ >10MB sent = +50            │
├─────────────────────────────────┤
│ Network Diversity (0-30 pts)    │
│ └─ >5 destinations = +30        │
├─────────────────────────────────┤
│ File Operations (0-40 pts)      │
│ └─ >10 deletes = +40            │
│ └─ Sensitive files = +25        │
├─────────────────────────────────┤
│ Permission Changes (0-20 pts)   │
│ └─ chmod 777 = +20              │
└─────────────────────────────────┘
         TOTAL RISK SCORE

Risk Levels:
├─ 0-20   → Normal (green)
├─ 20-50  → Suspicious (yellow)
├─ 50-80  → High risk (orange)
└─ 80+    → Critical (red) → BLOCK
```

---

## Use Cases

### 1. AI Agent Sandboxing
```
Scenario: Run untrusted AI agent in controlled environment
Solution: Deploy Dhi in ALERT mode
Result:   Monitor for exfiltration attempts, alert operator
```

### 2. Container Security
```
Scenario: Protect container workloads
Solution: Deploy Dhi with cgroup awareness
Result:   Per-container monitoring & enforcement
```

### 3. Compliance & Audit
```
Scenario: Prove no data left secure environment
Solution: Dhi logs all network/file activity
Result:   Complete audit trail for compliance
```

### 4. Incident Response
```
Scenario: Investigate suspicious process
Solution: Enable Dhi BLOCK mode
Result:   Halt attack progression, collect evidence
```

---

## Files & Structure

```
dhi/
├── dhi.py                 # Main runtime protection system
├── dhi_kernel.c           # eBPF kernel program
├── dhi_simple.py          # Simplified learning version
├── README.md              # Full documentation
├── ARCHITECTURE.md        # Technical deep-dive
├── QUICKSTART.md          # 5-minute setup guide
├── deploy.sh              # Deployment automation
├── config.json            # Configuration file
└── integrations/
    ├── slack.py           # Slack alerting
    ├── prometheus.py      # Prometheus metrics
    └── siem.py            # SIEM integration
```

---

## Deployment

### Systemd Service
```bash
# Deploy as system service
sudo systemctl start dhi
sudo systemctl enable dhi
sudo systemctl status dhi

# View logs
sudo journalctl -u dhi -f
```

### Docker
```bash
docker run -it --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug \
  dhi:latest \
  --level alert
```

### Kubernetes
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: dhi-protector
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: dhi
    image: dhi:latest
    securityContext:
      privileged: true
    args: ["--level", "alert"]
```

---

## Troubleshooting

### Common Issues

**Q: Permission denied**
```bash
A: Run with sudo
   sudo dhi.py --level alert
```

**Q: BPF program load failed**
```bash
A: Check kernel version (need 5.8+)
   uname -r
```

**Q: No events detected**
```bash
A: Check if tracepoints are enabled
   cat /proc/sys/kernel/perf_event_paranoid
```

**Q: High CPU usage**
```bash
A: Use LOG mode first to verify activity
   sudo dhi.py --level log
```

---

## Performance

```
Overhead:        <1% CPU at 1k syscalls/sec
Memory:          5-10 MB total
Ring Buffer:     256 entries, ~50KB
Latency:         <100μs per event
Throughput:      10k+ syscalls/sec
```

---

## Security Considerations

### What Dhi Protects Against
✅ Network data transmission
✅ File deletion/modification
✅ Permission escalation setup
✅ Behavioral anomalies

### What Dhi Cannot Protect Against
❌ In-memory data access
❌ Direct kernel module attacks
❌ Timing-based side channels
❌ File content inspection (metadata only)

---

## Philosophy

> **Dhi** means "Intellect" - the faculty of clear perception.
> 
> This system embodies that principle: it sees what others cannot,
> understands the context of every action, and makes intelligent
> decisions to protect your infrastructure.
>
> Ancient wisdom applied to modern security.

---

## References

- **eBPF**: https://ebpf.io/
- **BCC Tools**: https://github.com/iovisor/bcc
- **Sanskrit Etymology**: धी (Dhi) - Vedic root meaning intellect/perception
- **Security Papers**: USENIX Security, ACM CCS archives

---

## License

MIT License - Free for research, education, and production use.

## Support

- 📖 Documentation: See README.md, ARCHITECTURE.md
- 🐛 Issues: GitHub Issues
- 💬 Discussion: GitHub Discussions
- 📧 Contact: hello@dhi.io

---

**Dhi - Where Ancient Wisdom Meets Modern Security** 🧠🛡️
