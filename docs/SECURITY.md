# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Dhi, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email security concerns to: **sashank@seconize.co**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### Severity Definitions

| Severity | Description |
|----------|-------------|
| **Critical** | Remote code execution, credential theft, complete bypass of security controls |
| **High** | Significant data exposure, denial of service, privilege escalation |
| **Medium** | Limited data exposure, partial bypass of controls |
| **Low** | Minor information disclosure, requires unlikely conditions |

## Security Best Practices for Users

### Deployment

1. **Never expose to public network**
   ```bash
   # GOOD: Bind to localhost only
   dhi proxy --port 8080  # Binds to 127.0.0.1 by default
   
   # BAD: Don't do this
   # Exposing metrics to 0.0.0.0 is disabled by default
   ```

2. **Run with least privileges**
   ```bash
   # Create dedicated user
   sudo useradd -r -s /bin/false dhi
   
   # Run as non-root (eBPF requires CAP_BPF, CAP_PERFMON)
   sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/dhi
   ```

3. **Enable blocking mode in production**
   ```bash
   dhi proxy --port 8080 --level block --block-secrets
   ```

### Configuration

1. **Protect configuration files**
   ```bash
   chmod 600 ~/.config/dhi/config.toml
   ```

2. **Rotate Slack webhooks** regularly

3. **Review alerts** before enabling auto-blocking

### Monitoring

1. **Check logs regularly**
   ```bash
   journalctl -u dhi-proxy -f
   ```

2. **Monitor metrics** for anomalies
   ```bash
   curl http://localhost:9090/metrics
   ```

## Security Features

Dhi includes these security protections:

| Feature | Description |
|---------|-------------|
| Secrets Detection | 20+ patterns for API keys, tokens, passwords |
| PII Detection | SSN, credit cards, emails, phone numbers |
| Prompt Injection | Pattern matching for injection attempts |
| Jailbreak Detection | DAN mode, developer mode, etc. |
| Budget Control | Prevent runaway LLM costs |
| Tool Risk Analysis | Block dangerous tool invocations |

## Known Limitations

1. **HTTPS Inspection**: Currently tunnels HTTPS without inspection. Full MITM inspection requires CA certificate setup (planned for v0.2).

2. **eBPF**: Only available on Linux with kernel 5.8+. Requires elevated privileges.

3. **Pattern-based Detection**: Can be bypassed with novel encoding or obfuscation. Defense in depth recommended.

## Acknowledgments

We thank the security researchers who have helped improve Dhi:

- (Your name could be here!)

## PGP Key

For encrypted communications, use our PGP key:

```
(PGP key to be added)
```
