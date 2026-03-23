# Non-Linux Runtime Note (macOS/Windows)

Dhi is Linux-first. The primary production mode is eBPF on Linux.

On macOS and Windows:
- only proxy mode is currently available
- this path is currently untested and should be treated as best-effort
- GitHub Releases do not publish macOS/Windows binaries at this time
- you must build your own local binary from source

## What this means

- HTTPS payload content is not inspected in proxy mode (hostname-level visibility only)
- eBPF SSL interception and kernel-level monitoring are Linux-only
- run one mode at a time in production

## Build your own binary (required on macOS/Windows)

```bash
cargo build --release
```

Binary path:
- macOS/Linux: `./target/release/dhi`
- Windows: `./target/release/dhi.exe`

Then start proxy mode with your local binary.

## Minimal proxy setup

Start Dhi in proxy mode:

```bash
./target/release/dhi proxy --port 18080
```

Configure clients/tools:

```bash
export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
```

PowerShell equivalent:

```powershell
$env:HTTP_PROXY = "http://127.0.0.1:18080"
$env:HTTPS_PROXY = "http://127.0.0.1:18080"
```

## Recommendation

For production security coverage, use Linux eBPF mode whenever possible.
