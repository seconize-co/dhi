# Dhi Developer Guide

> Building, testing, and debugging Dhi — for developers contributing to the project

---

## Quick Start: Build from Source

For development and testing:

```bash
# Clone repository
git clone https://github.com/seconize-co/dhi.git
cd dhi

# Build debug binary (faster incremental builds)
cargo build

# Binary is at: ./target/debug/dhi

# Build release binary (optimized)
cargo build --release

# Binary is at: ./target/release/dhi
```

---

## Build eBPF Program

The eBPF SSL interception program must be compiled separately:

```bash
cd bpf

# Compile eBPF object file
clang -O2 -g -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o

# For development (faster, unoptimized):
clang -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o
```

**Install locally for testing:**

```bash
mkdir -p /tmp/dhi_local
cp dhi_ssl.bpf.o /tmp/dhi_local/

# Run Dhi with local eBPF object
cd ..
./target/debug/dhi --ebpf-path /tmp/dhi_local/dhi_ssl.bpf.o --level alert
```

**System-wide installation (production):**

```bash
sudo mkdir -p /usr/share/dhi
sudo cp dhi_ssl.bpf.o /usr/share/dhi/
```

---

## Architecture: How eBPF Works

### Execution Flow

1. **Dhi starts** → loads eBPF programs into the kernel
2. **Kernel hooks SSL** → intercepts OpenSSL/BoringSSL/GnuTLS function calls:
   - `SSL_read` (after decryption)
   - `SSL_write` (before encryption)
3. **Plaintext captured** → SSL payload accessible before encryption/after decryption
4. **Analysis engine** → scans for secrets, PII, injection attempts
5. **Decisions made** → alert, block, or log based on configuration
6. **Process signal** (block mode only) → send SIGTERM/SIGKILL to enforce block

### Why eBPF?

- **Kernel-level interception**: No proxy, no certificate injection, no app modification needed
- **Transparent**: All OpenSSL-using applications automatically monitored
- **Efficient**: Minimal overhead; only relevant traffic analyzed
- **Secure**: Runs with minimal capabilities (CAP_BPF, CAP_PERFMON)

### Limitations

- **Linux only**: eBPF is a Linux kernel feature (requires kernel 5.4+)
- **SSL libraries only**: Only OpenSSL, BoringSSL, GnuTLS intercepted; custom crypto bypasses protection
- **Process signal dependencies**: Block action requires `/proc/<pid>/` accessibility and Linux signals

### File Structure

```
dhi/
├── src/
│   ├── ebpf/
│   │   ├── mod.rs             # eBPF module entry
│   │   ├── linux.rs           # Linux eBPF loader (libbpf)
│   │   ├── ssl_hook.rs        # SSL uprobe attachment logic
│   │   ├── ssl_hook_test.rs   # SSL hook tests
│   │   └── stub.rs            # Stub for non-Linux
│   ├── agentic/
│   │   ├── mod.rs             # Detection pipeline
│   │   ├── pii_detector.rs    # PII patterns
│   │   ├── secrets_detector.rs # Secret scanning
│   │   ├── prompt_security.rs  # Injection detection
│   │   └── ...
│   ├── proxy.rs               # HTTP/HTTPS proxy implementation
│   └── server.rs              # Metrics & health endpoints
├── bpf/
│   ├── dhi_ssl.bpf.c          # eBPF source (kernel bytecode)
│   └── README.md              # eBPF build instructions
└── ...
```

---

## Development Environment Setup

### Prerequisites

Install build tools:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential cargo rustc clang llvm git

# Fedora/RHEL
sudo dnf install -y gcc-c++ cargo rustc clang llvm git

# macOS (for proxy development only; eBPF not supported)
brew install rust llvm
```

### Rust Toolchain

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Update Rust
rustup update

# Check version
cargo --version
rustc --version
```

### Linux Kernel Requirements

For eBPF development, ensure kernel >= 5.4:

```bash
# Check kernel version
uname -r

# If < 5.4, upgrade:
# Ubuntu: sudo apt-get install linux-image-generic-hwe-22.04
# Fedora: sudo dnf install kernel
# (then reboot)
```

---

## Testing

### Run Tests

```bash
# Unit tests for all agentic detectors
cargo test --lib agentic::

# eBPF-specific tests (Linux only)
cargo test --lib ebpf::

# Integration tests (requires sudo/eBPF support)
cargo test --test '*' -- --include-ignored --nocapture

# Proxy-mode tests (no eBPF needed)
cargo test --lib proxy_test
```

### Run End-to-End Security Tests

```bash
# Build test vectors and synthetic HTTPS clients
cd scripts
chmod +x security-e2e.sh
sudo ./security-e2e.sh

# Checks:
# - eBPF SSL hooks load correctly
# - Secrets detected in HTTPS traffic
# - PII detected on plaintext inspection
# - Block mode correctly kills offending processes
```

### Test with Copilot CLI

```bash
# 1. Install/update Copilot CLI
pip install copilot-cli --upgrade

# 2. Start Dhi with Copilot monitoring (see OPERATIONS.md)
sudo dhi --level alert

# 3. Run Copilot command through Dhi
copilot "explain this code"

# 4. Check detection logs
tail -f /tmp/log/dhi/dhi.log | grep -i copilot
```

### Local Test Setup (Development)

Create a test setup without system-wide installation:

```bash
# Build debug binaries
cargo build
cd bpf && clang -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o && cd ..

# Create local directories
mkdir -p /tmp/dhi-dev/{bin,bpf,config,logs}

# Copy artifacts
cp target/debug/dhi /tmp/dhi-dev/bin/
cp bpf/dhi_ssl.bpf.o /tmp/dhi-dev/bpf/
cp dhi.toml.example /tmp/dhi-dev/config/dhi.toml

# Run locally
sudo /tmp/dhi-dev/bin/dhi \
  --config /tmp/dhi-dev/config/dhi.toml \
  --ebpf-path /tmp/dhi-dev/bpf/dhi_ssl.bpf.o \
  --level alert -v
```

---

## Debugging eBPF

### Check Kernel BTF Support

BTF (BPF Type Format) is required for modern eBPF programs:

```bash
# Check if kernel has BTF support
ls -la /sys/kernel/btf/vmlinux

# If missing, kernel doesn't support BTF (needs rebuild or kernel upgrade)
```

### View eBPF Programs Loaded

```bash
# List all eBPF programs
sudo bpftool prog list

# Show detailed info for Dhi programs
sudo bpftool prog list | grep dhi

# Dump eBPF bytecode (for advanced debugging)
sudo bpftool prog dump xlated name dhi_ssl_read
```

### View eBPF Maps (Shared State)

```bash
# List eBPF maps
sudo bpftool map list

# Dump map contents (useful for debugging state)
sudo bpftool map dump name event_ringbuf
```

### Monitor eBPF Events

```bash
# Real-time trace (if Dhi is running)
sudo trace-cmd record -e kprobes -l 'uprobe_ssl*'

# Alternative: use lesser-known bpftrace (advanced)
sudo bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libssl.so.3:SSL_read { @count++ }' -i 5
```

### Perf Event Paranoia Issues

If you see `perf_event_open failed` errors:

```bash
# Check current paranoia level
cat /proc/sys/kernel/perf_event_paranoid

# Lower it (allows uprobes for non-root users when CAP_BPF is present)
echo 'kernel.perf_event_paranoid=1' | sudo tee /etc/sysctl.d/99-dhi-ebpf.conf
sudo sysctl --system

# Verify fix
cat /proc/sys/kernel/perf_event_paranoid
```

---

## eBPF Troubleshooting & Deep Debugging

### Dhi Can't Attach SSL Uprobes

**Symptom:** Logs show `No SSL uprobes attached` or `Failed to attach uprobe`.

**Diagnosis:**

```bash
# Check which OpenSSL versions are present
ldd /bin/openssl | grep libssl
ls -la /usr/lib/x86_64-linux-gnu/libssl*

# Confirm kernel BTF support
ls /sys/kernel/btf/vmlinux

# Verify eBPF capabilities
capsh --print | grep CAP_BPF
```

**Fix:**

1. **Ensure systemd service has correct capabilities:**
   ```bash
   sudo cp ops/systemd/dhi.service /etc/systemd/system/dhi.service
   sudo systemctl daemon-reload
   sudo systemctl restart dhi
   ```

2. **Lower perf_event_paranoia:**
   ```bash
   echo 'kernel.perf_event_paranoid=1' | sudo tee /etc/sysctl.d/99-dhi-ebpf.conf
   sudo sysctl --system
   ```

3. **Verify fix:**
   ```bash
   sudo journalctl -u dhi -n 50 | grep -E 'Attached uprobe|Failed to attach'
   ```

### eBPF Program Doesn't Load

**Symptom:** `load_bpf_program failed`.

```bash
# Check kernel messages
sudo dmesg | tail -20 | grep -i bpf

# Common causes:
# - Kernel too old (need >= 5.4)
# - BTF missing
# - Verifier rejected program

# Rebuild with verbose output
cargo build --features ebpf-debug
```

### Monitoring Uprobe Attachment

```bash
# Monitor attach/detach in real-time
sudo cat /sys/kernel/debug/tracing/uprobe_events

# Watch trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep dhi
```

---

## Copilot CLI eBPF Setup (For Testing)

When running Copilot CLI tests through Dhi, configure explicit SSL target detection:

```bash
# 1. Find Copilot binary path
command -v copilot
readlink -f "$(command -v copilot)"

# Example: /home/user/.local/bin/copilot

# 2. Create systemd override (adjust path to match your installation)
sudo systemctl edit dhi
```

Add this override content:

```ini
[Service]
Environment=DHI_SSL_EXTRA_TARGETS=/home/<user>/.local/bin/copilot
StandardOutput=append:/tmp/log/dhi/dhi.log
StandardError=append:/tmp/log/dhi/dhi.log
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart dhi
```

Verify Copilot target was discovered:

```bash
# Should see lines like:
# "Found runtime SSL target: /home/user/.local/bin/copilot"
# "Attached uprobe_ssl_read for /home/user/.local/bin/copilot"
grep -aE 'Found runtime SSL target|Attached uprobe_ssl.*copilot' /tmp/log/dhi/dhi.log
```

---

## Contributing

### Code Standards

- **Rust formatting:** `cargo fmt`
- **Linting:** `cargo clippy --all-targets`
- **Tests:** All new features require unit tests
- **Documentation:** Add doc comments to public APIs

### Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes and add tests
4. Run tests: `cargo test`
5. Format and lint: `cargo fmt && cargo clippy`
6. Commit with clear messages
7. Push and open a pull request

### eBPF Development Tips

- Changes to `bpf/dhi_ssl.bpf.c` require kernel recompilation and Dhi binary rebuild
- Test eBPF changes with: `cargo test --lib ebpf:: -- --include-ignored`
- Use `bpftool` to inspect loaded programs
- Keep eBPF code minimal; complexity should be in user-space detection (Rust)

---

## Documentation

- **Architecture:** See [CTO_GUIDE.md](CTO_GUIDE.md)
- **Operations:** See [OPERATIONS.md](OPERATIONS.md)
- **Security:** See [SECURITY.md](SECURITY.md)
- **API Integration:** See [INTEGRATION.md](INTEGRATION.md)

---

## Support

- GitHub Issues: https://github.com/seconize-co/dhi/issues
- Discussions: https://github.com/seconize-co/dhi/discussions

*Dhi is open source under MIT license.*
