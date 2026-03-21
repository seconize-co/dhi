# Dhi - Rust Implementation 🦀

> High-performance runtime intelligence & protection system for AI agents

## Why Rust?

| Metric | Python | Rust |
|--------|--------|------|
| Event throughput | ~10K/sec | ~1M+/sec |
| Memory usage | ~50-100 MB | ~5-10 MB |
| Latency | GC pauses | Predictable |
| Binary size | Requires Python | Single 5MB binary |
| Dependencies | pip install ... | None at runtime |

## Building

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Run with demo
cargo run -- demo
```

## Usage

```bash
# Basic monitoring (alert mode)
sudo ./dhi --level alert

# Block mode (production)
sudo ./dhi --level block

# With whitelisting
sudo ./dhi --level alert \
    --whitelist-ip 10.0.0.0 \
    --whitelist-file /var/log/

# Agentic-only mode (no eBPF)
./dhi --level alert --no-ebpf

# Run demo
./dhi demo
```

## Architecture

```
dhi-rs/
├── Cargo.toml              # Dependencies
├── src/
│   ├── main.rs             # CLI entry point
│   ├── lib.rs              # Library root
│   ├── agentic/            # Agentic runtime features
│   │   ├── mod.rs          # Main agentic runtime
│   │   ├── llm_monitor.rs  # LLM API tracking
│   │   ├── tool_monitor.rs # Tool invocation monitoring
│   │   ├── prompt_security.rs # Prompt security analysis
│   │   ├── memory_protection.rs # Memory tampering detection
│   │   └── mcp_monitor.rs  # MCP protocol parsing
│   ├── detection/          # Detection engine
│   │   └── mod.rs          # Risk scoring & rules
│   ├── ebpf/               # eBPF kernel monitoring
│   │   ├── mod.rs          # eBPF module
│   │   └── stub.rs         # Non-Linux stub
│   └── monitor/            # Unified monitoring
│       └── mod.rs          # Stats & orchestration
```

## Features

### Kernel-Level (eBPF) - Linux Only
- Syscall monitoring (openat, sendto, unlinkat, etc.)
- File operation tracking
- Network transmission detection
- <1% CPU overhead

### Agentic Runtime - All Platforms
- LLM API call tracking with cost estimation
- Tool invocation monitoring with risk analysis
- MCP protocol parsing
- Prompt injection detection
- Jailbreak attempt detection
- Memory/context tampering protection
- Budget controls

## Demo Output

```
═══════════════════════════════════════════════════════════════════
  ██████╗ ██╗  ██╗██╗
  ██╔══██╗██║  ██║██║     धी - Intellect | Perception | Vision
  ██║  ██║███████║██║     Runtime Intelligence & Protection System
  ██║  ██║██╔══██║██║
  ██████╔╝██║  ██║██║     Protection Level: ALERT
  ╚═════╝ ╚═╝  ╚═╝╚═╝     Written in Rust 🦀
═══════════════════════════════════════════════════════════════════

📍 Registering agent...
   Agent registered: demo-agent-001 (framework: langchain)

📍 Simulating LLM calls...
   LLM Call: 700 tokens, $0.0330, risk: 0
   🚨 ALERT: ["prompt_injection_detected"]

📍 Simulating tool calls...
   Tool: web_search - allowed: true, risk: low
   Tool: shell_execute - allowed: true, risk: critical
   Tool: sudo rm -rf - allowed: false, risk: low

📍 Testing memory protection...
   Memory verified (unchanged): true
   Memory verified (tampered): false, tampered: true

═══════════════════════════════════════════════════════════════════
  AGENT STATISTICS
═══════════════════════════════════════════════════════════════════
{
  "agent_id": "demo-agent-001",
  "llm_calls": 2,
  "tool_invocations": 3,
  "total_tokens": 1800,
  "total_cost_usd": 0.0339,
  "risk_score": 85
}
```

## Configuration

### Config File (dhi.toml)

```toml
protection_level = "alert"
max_budget_usd = 10.0
max_tokens_per_call = 100000
enable_ebpf = true
enable_agentic = true

whitelist_ips = ["127.0.0.1", "10.0.0.0"]
whitelist_files = ["/var/log/", "/tmp/"]

tool_denylist = ["sudo", "rm -rf", "chmod 777"]
tool_allowlist = []
```

### Environment Variables

```bash
export DHI_LOG=debug          # Log level
export DHI_CONFIG=/etc/dhi.toml  # Config path
```

## Performance

```
Benchmark: 1M events/sec processing

CPU:     ~5% at 100K events/sec
Memory:  ~8 MB RSS
Latency: <10 microseconds per event
Binary:  ~5 MB stripped
```

## License

MIT License
