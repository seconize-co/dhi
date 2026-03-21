# Integrating Dhi with AI Coding Assistants

> How to use Dhi with Claude Code, GitHub Copilot CLI, Cursor, and other AI tools

---

## Overview

Dhi can protect AI coding assistants through HTTP proxy mode:

| Mode | How It Works | Setup Complexity |
|------|--------------|------------------|
| **Proxy Mode** | Intercept HTTP traffic to LLM APIs | Low |

---

## Proxy Mode Setup

Run Dhi as an HTTP proxy that intercepts all LLM API calls.

### Step 1: Start Dhi Proxy

```bash
# Build Dhi
cargo build --release

# Start Dhi in proxy mode (alert only)
./target/release/dhi proxy --port 8080

# With blocking enabled for secrets
./target/release/dhi proxy --port 8080 --block-secrets

# With blocking enabled for secrets and PII
./target/release/dhi proxy --port 8080 --block-secrets --block-pii

# With Slack alerts
./target/release/dhi proxy --port 8080 --slack-webhook "https://hooks.slack.com/..."
```

### Step 2: Configure Your AI Tool

#### Claude Code

Set environment variables before running:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
claude
```

Or add to your shell profile (`~/.bashrc` or `~/.zshrc`):

```bash
# Dhi protection for AI tools
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

#### GitHub Copilot CLI

```bash
# Set proxy for Copilot
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# Run Copilot CLI
gh copilot suggest "how do I..."
```

#### Cursor

In Cursor settings (`Settings > Proxy`):
- HTTP Proxy: `http://127.0.0.1:8080`
- HTTPS Proxy: `http://127.0.0.1:8080`

---

## What Gets Protected

When running in proxy mode, Dhi scans all traffic:

| Direction | Protection |
|-----------|------------|
| **Requests (Prompts)** | |
| - Secrets in prompts | API keys, tokens, passwords |
| - PII in prompts | SSN, credit cards, emails |
| - Prompt injection | Jailbreak attempts |
| **Responses** | |
| - Secrets in output | Leaked credentials |
| - PII in output | Sensitive data exposure |

### Example Detections

```
[ALERT] Request to api.openai.com: Secrets detected: ["aws_access_key"]
[BLOCKED] Request to api.anthropic.com: Prompt injection detected
[ALERT] Response from api.openai.com: PII detected: ["email", "ssn"]
```

---

## Quick Setup Script

Save as `setup-dhi.sh` (Linux/macOS):

```bash
#!/bin/bash

# Build Dhi
cargo build --release

# Create systemd service for proxy (Linux)
sudo tee /etc/systemd/system/dhi-proxy.service << EOF
[Unit]
Description=Dhi Security Proxy for AI Agents
After=network.target

[Service]
Type=simple
ExecStart=$(pwd)/target/release/dhi proxy --port 8080 --block-secrets
Restart=always
User=$USER

[Install]
WantedBy=multi-user.target
EOF

# Start service
sudo systemctl daemon-reload
sudo systemctl enable dhi-proxy
sudo systemctl start dhi-proxy

# Add to shell profile
echo 'export HTTP_PROXY=http://127.0.0.1:8080' >> ~/.bashrc
echo 'export HTTPS_PROXY=http://127.0.0.1:8080' >> ~/.bashrc

echo "✅ Dhi proxy running on port 8080"
echo "Restart your terminal or run: source ~/.bashrc"
```

---

## Protection Levels

| Flag | Behavior |
|------|----------|
| (default) | Log and alert only |
| `--level alert` | Same as default - log and alert |
| `--level block` | Block dangerous requests |
| `--block-secrets` | Block requests containing secrets |
| `--block-pii` | Block requests containing PII |

**Recommended:** Start with alert mode to understand what's being detected, then enable blocking.

---

## Verification

### Check Dhi is Running

```bash
# Check if proxy is listening
# Linux/macOS
netstat -tlnp | grep 8080
# Or
lsof -i :8080

# Windows
netstat -an | findstr 8080
```

### Test the Proxy

```bash
# Make a request through the proxy
curl -x http://127.0.0.1:8080 https://httpbin.org/get

# Test secret detection (should trigger alert)
curl -x http://127.0.0.1:8080 \
  -d '{"prompt": "My API key is sk-proj-abc123"}' \
  https://httpbin.org/post
```

---

## Logs and Metrics

### View Proxy Logs

```bash
# If running manually with verbose
./target/release/dhi proxy --port 8080 -v

# If running as systemd service
journalctl -u dhi-proxy -f
```

### Example Log Output

```
2025-01-15T10:30:01 INFO Dhi proxy listening on 127.0.0.1:8080
2025-01-15T10:30:15 WARN [ALERT] api.openai.com: Secrets detected in request: ["openai_api_key"]
2025-01-15T10:30:22 WARN [ALERT] api.anthropic.com: Prompt injection attempt detected
2025-01-15T10:30:45 WARN [BLOCKED] api.openai.com: Credentials detected: ["aws_secret_key"]
```

---

## Troubleshooting

### Proxy Not Working

```bash
# Check if Dhi is listening
netstat -tlnp | grep 8080

# Test proxy directly
curl -v -x http://127.0.0.1:8080 https://example.com
```

### HTTPS Tunneling

Dhi uses CONNECT tunneling for HTTPS, which means:
- Connection establishment is logged
- Encrypted content is tunneled (not decrypted)
- For full HTTPS inspection, a future version will support CA certificate generation

### Tool Ignoring Proxy

Some tools have their own proxy configuration:
- Check tool-specific settings
- Some Node.js tools need `NODE_TLS_REJECT_UNAUTHORIZED=0`
- Some tools need explicit proxy configuration in their config files

---

## Security Considerations

1. **Dhi sees traffic** - Run only on your local machine
2. **Bind to localhost** - Never expose proxy to network (`127.0.0.1` only)
3. **Start in alert mode** - Review detections before enabling blocking
4. **Check logs regularly** - Monitor for false positives

---

## Summary

| AI Tool | Integration Method |
|---------|-------------------|
| Claude Code | `HTTP_PROXY=http://127.0.0.1:8080` |
| GitHub Copilot CLI | `HTTP_PROXY=http://127.0.0.1:8080` |
| Cursor | Settings > Proxy |
| VS Code Copilot | Settings > Http: Proxy |
| Any CLI tool | Environment variables |

**Minimum setup:**
```bash
# Terminal 1: Start Dhi
dhi proxy --port 8080 --block-secrets

# Terminal 2: Use AI tool with proxy
HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080 claude
```
