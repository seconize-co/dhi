# Copilot Observability: Design, Attempts, Validation, and Current Gap

## Purpose

This document records what was implemented and tested to restore reliable Copilot
traffic observability in Dhi, with emphasis on marker-correlated security evidence
(secret/PII/injection) for release gating.

It is intended as an engineering handoff and decision record.

## Problem Statement

For Copilot CLI `1.0.12`, Dhi consistently captured SSL traffic and produced global
alert deltas, but Copilot e2e marker-correlation remained unsupported (`exit 42`):

- Copilot commands succeeded.
- SSL event counters increased (`ssl_events_copilot`).
- Security alerts increased in aggregate.
- Per-test marker-correlated category evidence did not consistently materialize.

This created a release-gate ambiguity: transport visibility exists, but deterministic
prompt-level attribution for positive vectors is not yet reliable.

## High-Level Design Goals

1. Preserve release safety and avoid false green.
2. Improve extraction depth for framed/compressed Copilot traffic.
3. Improve harness attribution logic for delayed/asynchronous processing.
4. Keep compatibility semantics explicit (`supported|failed|unsupported`).

## Implemented Changes

### 1) SSL payload decoding and extraction hardening (`src/ebpf/ssl_hook.rs`)

Implemented layered extraction to surface marker and security-relevant text from
binary/framed streams:

- Increased analysis corpus and candidate handling.
- Added compression decode attempts:
  - gzip
  - zlib
  - brotli
  - zstd
- Added frame extraction:
  - HTTP/2 DATA/HEADERS-style frame payload scanning
- Added HTTP/2 per-stream payload reconstruction (segmented DATA merge).
- Added gRPC length-prefixed message extraction.
- Added printable-fragment extraction from binary payloads.
- Added env-gated forensic payload/frame dumps:
  - `DHI_COPILOT_FORENSIC_DUMP=1`
  - bounded hex samples and frame snapshots.

### 2) Copilot e2e harness hardening (`scripts/copilot-cli-e2e.sh`)

Added and extended correlation mechanics:

- Explicit alert log path support (`--alert-log-file`) and autodiscovery fallback.
- Compatibility line output:
  - `COMPATIBILITY: copilot_cli_semver=... marker_correlation=...`
- Marker correlation sources:
  - alert JSON marker counting by category
  - runtime log marker counting by category
  - PID-window correlation checks
  - time-window fallback checks
- Added run/session controls:
  - unique per-test Copilot session via `--resume=<uuid>`
  - configurable `--correlation-window-sec` (default 60s)
- Added stronger attribution attempts:
  - marker presence counting
  - run-prefix counting
  - newly-created Copilot PID snapshot/delta window checks

### 3) Forensic + release workflow behavior

- Kept `exit 42` for unsupported marker-correlation environments to avoid false pass.
- Preserved release verify semantics to SKIP Copilot e2e when unsupported, instead of
  misreporting PASS.

## Validation Performed

### Unit/targeted tests

- `cargo test --all-features ssl_hook::tests -- --nocapture`
- Added new tests for:
  - HTTP/2 stream reconstruction
  - gRPC message extraction
  - printable fragment marker recovery

All targeted SSL hook tests passed during iterations.

### Runtime checks

- Rebuilt and redeployed service repeatedly.
- Verified service health and stats endpoints.
- Ran Copilot e2e harness repeatedly in alert mode with explicit log paths.
- Verified forensic log evidence:
  - HTTP/2 preface and binary frame structure visible.
  - Copilot SSL event flow active.

## What We Observed

Positive:

- Dhi clearly captures Copilot TLS plaintext at SSL hook points.
- Binary framing patterns are visible and partially decodable.
- Marker extraction improved in runtime logs (`[COPILOT RUN MARKER]` appears).

Still failing:

- Marker-correlated category evidence for per-test vectors is not deterministic.
- Harness still returns:
  - `marker_correlation=unsupported`
  - exit code `42`

## Why Current Fixes Are Not Sufficient

Despite stronger extraction and attribution, Copilot CLI traffic still exhibits:

- heavily framed async transport behavior,
- delayed/overlapping event emission across long-lived flows,
- category signals that are not reliably tied to the exact test marker line/path.

Net effect: attribution quality is insufficient for strict positive-test marker gating.

## Risk and Policy Decision (Current)

Current safe policy is:

- Keep compatibility skip (`exit 42`) for unsupported environments/versions.
- Do not convert to hard pass based only on global alert deltas.
- Do not hard-fail release solely on this until deterministic attribution path is proven.

## Next Engineering Steps (Recommended)

1. Add bounded HPACK decode for HEADERS/CONTINUATION payloads to expose compressed
   header content when marker-related metadata is encoded there.
2. Add optional alternate attach points at Copilot runtime boundaries where payloads
   are still plain JSON-RPC/text before framing/envelope transforms.
3. Extend alert metadata pipeline to carry correlation IDs from extraction stage where
   possible, reducing reliance on line-level marker regex.
4. Re-baseline harness pass criteria after (1)-(3), then decide whether to move from
   `unsupported` skip to strict fail/pass gate.

## Files Touched in This Effort

- `src/ebpf/ssl_hook.rs`
- `scripts/copilot-cli-e2e.sh`
- `Cargo.toml`
- `Cargo.lock`

## Current Status

- Build/tests: passing for targeted SSL hook suite.
- Runtime: Copilot traffic visible.
- Release behavior: Copilot e2e remains compatibility SKIP (`exit 42`) for Copilot
  CLI `1.0.12` in this environment.
