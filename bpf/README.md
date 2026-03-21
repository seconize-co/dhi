# Dhi eBPF Programs

This directory contains eBPF programs for kernel-level monitoring.

## Programs

### dhi_ssl.bpf.c

SSL/TLS traffic interception via uprobes. Captures plaintext data before encryption and after decryption.

**Hooked functions:**
- OpenSSL/BoringSSL: `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex`
- GnuTLS: `gnutls_record_recv`, `gnutls_record_send`

## Building

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Fedora/RHEL
sudo dnf install clang llvm libbpf-devel kernel-devel

# Arch Linux
sudo pacman -S clang llvm libbpf linux-headers
```

### Generate vmlinux.h (BTF)

```bash
# Option 1: From running kernel (if BTF enabled)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Option 2: From kernel image
bpftool btf dump file /boot/vmlinuz-$(uname -r) format c > vmlinux.h

# Option 3: Use bpftool to generate
bpftool gen vmlinux > vmlinux.h
```

### Compile

```bash
# Compile the SSL hook program
clang -O2 -g -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include \
  -I. \
  -c dhi_ssl.bpf.c \
  -o dhi_ssl.bpf.o

# Verify the program
llvm-objdump -S dhi_ssl.bpf.o
```

### Install

```bash
# Install to system path
sudo mkdir -p /usr/share/dhi
sudo cp dhi_ssl.bpf.o /usr/share/dhi/
```

## How It Works

### SSL_write (Outbound Traffic)

```
Application                    Kernel                    Network
    |                            |                          |
    | SSL_write(ssl, buf, len)   |                          |
    |--------------------------->|                          |
    |      [uprobe captures      |                          |
    |       plaintext 'buf']     |                          |
    |                            | (encrypt & send)         |
    |                            |------------------------->|
```

### SSL_read (Inbound Traffic)

```
Application                    Kernel                    Network
    |                            |                          |
    | SSL_read(ssl, buf, len)    |                          |
    |--------------------------->|                          |
    |      [uprobe saves args]   |                          |
    |                            | (receive & decrypt)      |
    |                            |<-------------------------|
    |<---------------------------|                          |
    |      [uretprobe captures   |                          |
    |       decrypted 'buf']     |                          |
```

## Security Considerations

1. **Requires root/CAP_BPF**: eBPF programs need elevated privileges
2. **Performance impact**: Minimal, but captures up to 16KB per operation
3. **Data sensitivity**: Captured data includes plaintext credentials
4. **Memory usage**: Ring buffer is 256KB by default

## Limitations

1. Only works on Linux (kernel 5.4+ recommended for BTF)
2. Requires the SSL library to be dynamically linked
3. Statically linked SSL or custom implementations won't be captured
4. Some applications may use unusual TLS libraries

## Troubleshooting

### Check if BTF is available

```bash
ls -la /sys/kernel/btf/vmlinux
```

### Check kernel version

```bash
uname -r
# Should be 5.4 or higher for full uprobe support
```

### Verify library paths

```bash
# Find OpenSSL
ldconfig -p | grep libssl

# Find GnuTLS
ldconfig -p | grep libgnutls
```

### Test uprobe attachment

```bash
# List available uprobes
sudo cat /sys/kernel/debug/tracing/uprobe_events

# Test attach (as root)
echo 'p:ssl_write /usr/lib/x86_64-linux-gnu/libssl.so.3:SSL_write' | \
  sudo tee /sys/kernel/debug/tracing/uprobe_events
```
