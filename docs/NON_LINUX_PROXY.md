# Non-Linux Runtime Note (macOS/Windows)

Dhi is Linux-first. The primary production mode is eBPF on Linux.

On macOS and Windows:
- only proxy mode is currently available
- this path is **beta, untested, and experimental**
- treat this path as best-effort and validate thoroughly before production use
- GitHub Releases do not publish macOS/Windows binaries at this time
- you must build your own local binary from source

> ⚠️ Proxy mode on non-Linux is beta/untested/experimental and not the recommended production path.

## What this means

- HTTPS payload content is not inspected in proxy mode (hostname-level visibility only)
- eBPF SSL interception and kernel-level monitoring are Linux-only
- if the proxy process is down, clients configured to use it may fail closed

| Proxy Mode Can See | Proxy Mode CANNOT See |
|-------------------|----------------------|
| ✅ Hostname (api.openai.com) | ❌ Request body (prompts) |
| ✅ Connection timing | ❌ Response body (completions) |
| ✅ Bytes transferred | ❌ Secrets/PII in payload |

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

## Optional failover pattern (non-Linux compatibility path)

If you must keep tools running when Dhi proxy is unavailable, use client-side failover.

PAC file example:

```javascript
function FindProxyForURL(url, host) {
	// Try Dhi proxy first, then direct
	return "PROXY 127.0.0.1:18080; DIRECT";
}
```

Shell wrapper example:

```bash
#!/bin/bash
if nc -z 127.0.0.1 18080 2>/dev/null; then
	export HTTP_PROXY=http://127.0.0.1:18080
	export HTTPS_PROXY=http://127.0.0.1:18080
else
	echo "WARNING: Dhi proxy not running, continuing without Dhi proxy"
	unset HTTP_PROXY HTTPS_PROXY
fi
exec "$@"
```

## Recommendation

For production security coverage, use Linux eBPF mode whenever possible.
Use non-Linux proxy mode only when Linux eBPF deployment is not possible.
