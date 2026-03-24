# Framework Onboarding Guide

This guide explains how to add support for a new agent framework (for example: OpenCode, Claude-based wrappers, CrewAI variants) in Dhi.

## Scope

Most framework additions are **fingerprinting + tests + docs** changes only.

You usually do **not** need to change eBPF SSL probes unless the framework uses a different TLS/runtime stack.

## Quick Checklist

1. Add framework enum variant in `src/agentic/fingerprint.rs` (`AgentFramework`).
2. Add display mapping in `name()` and category mapping in `category()`.
3. Add detection rules in `detect_framework()` with this order:
   - process name (highest confidence)
   - user-agent
   - framework-specific headers
   - request body markers (lowest confidence)
4. Add focused tests in `src/agentic/fingerprint.rs` test section:
   - process-based detection test
   - user-agent/header/body detection tests
   - negative test (ensure no false match on common traffic)
5. Validate runtime output from `/api/agents` includes the new framework name.
6. Update docs where framework support is listed (`docs/USER_GUIDE.md`, optionally `README.md`).
7. Include evidence in PR description (test output and sample detection log/API snippet).

## SSL/eBPF Probe Impact Checklist (Important)

When adding a framework, verify whether existing SSL capture still applies:

1. Framework uses dynamically linked OpenSSL/BoringSSL/GnuTLS:
   - No probe code change required in most cases.
2. Framework uses Rustls/NSS/custom TLS or static linking:
   - Existing SSL uprobes may not capture payload.
   - You may need new probes/symbol targets in `bpf/dhi_ssl.bpf.c` and loader/attach logic in `src/ebpf/ssl_hook.rs`.
3. Validate in Linux eBPF mode:
    - SSL probes attach successfully.
    - SSL raw events are emitted.
    - Framework classification is correct in `/api/agents`.
4. For Copilot CLI compatibility specifically:
   - Confirm runtime discovery still handles live executable mappings via `/proc/<pid>/exe`.
   - Avoid assuming static binary paths are stable across updates/reinstalls.
   - Validate `/api/stats` deltas for `ssl_events` and `ssl_events_copilot` with Copilot traffic.

## Detection Rule Design Notes

- Prefer **specific signals** over generic substring checks.
- Avoid adding broad body markers that can cause false positives.
- Keep generic fallbacks last (`Unknown`).
- If a framework can run under multiple process names, add all known aliases.

## PR Quality Bar

For framework onboarding PRs, include:

- Code changes in fingerprinting logic
- Tests for positive and negative paths
- Documentation updates
- Notes on SSL/eBPF impact (required even if "no change needed")

## Related Files

- `src/agentic/fingerprint.rs`
- `src/agentic/mod.rs`
- `src/ebpf/linux.rs`
- `src/ebpf/ssl_hook.rs`
- `bpf/dhi_ssl.bpf.c`
- `docs/USER_GUIDE.md`
- `docs/OPERATIONS.md`
