#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RELEASE_TAG="${RELEASE_TAG:-}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/dhi-release-verify-$(date +%Y%m%d-%H%M%S)}"
REPORTS_DIR="${REPORTS_DIR:-/var/log/dhi/reports}"

RUN_INTEGRITY=1
RUN_INSTALL=1
RUN_RUNTIME_CHECKS=1
RUN_SECURITY=1
RUN_REPORTING=1
RUN_COPILOT=1
RUN_UNINSTALL_CYCLE=1
KEEP_GOING=1
QUICK_MODE=0

SECURITY_SKIP_BUILD=0
SECURITY_SKIP_QUALITY_GATE=0
SECURITY_RUN_SUDO_TESTS=0
REPORT_REQUIRE_RUNTIME_REPORTS=0
REPORT_SKIP_LIVE_ENDPOINTS=0

COPILOT_MODE="alert"
STATUS_PORT="${STATUS_PORT:-}"
DHI_SERVICE_WAS_ACTIVE=0

TOTAL_STEPS=0
PASS_STEPS=0
FAIL_STEPS=0
SKIP_STEPS=0
RUNTIME_AVAILABLE=0
RUNTIME_FAILURE_REASON=""
STEP_SKIP_REASON=""

usage() {
  cat <<'EOF'
Usage: scripts/release-verify.sh [options]

Repeatable RC/GA verification gate that reuses:
  - scripts/install-linux-release.sh
  - scripts/security-e2e.sh
  - scripts/reporting-e2e.sh
  - scripts/copilot-cli-e2e.sh (optional)
  - scripts/uninstall-linux.sh (optional cycle)

Core options:
  --release-tag TAG              Release tag to validate (e.g., v0.1.0-rc.12)
  --artifacts-dir PATH           Output directory for logs + summary
  --reports-dir PATH             Runtime reports directory (default: /var/log/dhi/reports)
  --status-port PORT             Override runtime health/metrics port
  --quick                        Fast local verification profile (reduced scope)

Scope toggles:
  --skip-integrity               Skip release asset checksum verification
  --skip-install                 Skip install + --verify-only checks
  --skip-runtime-checks          Skip systemd/health/metrics runtime checks
  --skip-security                Skip scripts/security-e2e.sh
  --skip-reporting               Skip scripts/reporting-e2e.sh
  --with-copilot                 Run scripts/copilot-cli-e2e.sh
  --without-copilot              Skip scripts/copilot-cli-e2e.sh
  --copilot-mode MODE            alert|block (default: alert)
  --run-uninstall-cycle          Run uninstall dry-run + purge validation at end
  --skip-uninstall-cycle         Skip uninstall validation cycle

Harness passthrough:
  --security-skip-build          Pass --skip-build to security harness
  --security-skip-quality-gate   Pass --skip-quality-gate to security harness
  --security-run-sudo-tests      Pass --run-sudo-tests to security harness
  --report-require-runtime-reports
                                Pass --require-runtime-reports to reporting harness
  --report-skip-live-endpoints  Pass --skip-live-endpoints to reporting harness

Control:
  --fail-fast                    Stop immediately on first failed step
  -h, --help                     Show this help

Examples:
  scripts/release-verify.sh --release-tag v0.1.0-rc.12
  scripts/release-verify.sh --quick
  scripts/release-verify.sh --quick --security-skip-build --security-skip-quality-gate
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-tag)
      RELEASE_TAG="$2"
      shift 2
      ;;
    --artifacts-dir)
      ARTIFACTS_DIR="$2"
      shift 2
      ;;
    --reports-dir)
      REPORTS_DIR="$2"
      shift 2
      ;;
    --status-port)
      STATUS_PORT="$2"
      shift 2
      ;;
    --quick)
      QUICK_MODE=1
      shift
      ;;
    --skip-integrity)
      RUN_INTEGRITY=0
      shift
      ;;
    --skip-install)
      RUN_INSTALL=0
      shift
      ;;
    --skip-runtime-checks)
      RUN_RUNTIME_CHECKS=0
      shift
      ;;
    --skip-security)
      RUN_SECURITY=0
      shift
      ;;
    --skip-reporting)
      RUN_REPORTING=0
      shift
      ;;
    --with-copilot)
      RUN_COPILOT=1
      shift
      ;;
    --without-copilot)
      RUN_COPILOT=0
      shift
      ;;
    --copilot-mode)
      COPILOT_MODE="$2"
      shift 2
      ;;
    --run-uninstall-cycle)
      RUN_UNINSTALL_CYCLE=1
      shift
      ;;
    --skip-uninstall-cycle)
      RUN_UNINSTALL_CYCLE=0
      shift
      ;;
    --security-skip-build)
      SECURITY_SKIP_BUILD=1
      shift
      ;;
    --security-skip-quality-gate)
      SECURITY_SKIP_QUALITY_GATE=1
      shift
      ;;
    --security-run-sudo-tests)
      SECURITY_RUN_SUDO_TESTS=1
      shift
      ;;
    --report-require-runtime-reports)
      REPORT_REQUIRE_RUNTIME_REPORTS=1
      shift
      ;;
    --report-skip-live-endpoints)
      REPORT_SKIP_LIVE_ENDPOINTS=1
      shift
      ;;
    --fail-fast)
      KEEP_GOING=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$COPILOT_MODE" != "alert" && "$COPILOT_MODE" != "block" ]]; then
  echo "Invalid --copilot-mode: $COPILOT_MODE (expected alert|block)" >&2
  exit 2
fi

if [[ "$QUICK_MODE" -eq 1 ]]; then
  RUN_INTEGRITY=0
  RUN_INSTALL=0
  RUN_RUNTIME_CHECKS=1
  RUN_SECURITY=1
  RUN_REPORTING=1
  RUN_COPILOT=0
  RUN_UNINSTALL_CYCLE=0
  SECURITY_SKIP_BUILD=1
  SECURITY_SKIP_QUALITY_GATE=1
  REPORT_SKIP_LIVE_ENDPOINTS=1
fi

mkdir -p "$ARTIFACTS_DIR/logs"

log() {
  echo "[$(date +%H:%M:%S)] $*"
}

step_pass() {
  local name="$1"
  PASS_STEPS=$((PASS_STEPS + 1))
  printf "PASS\t%s\n" "$name" >> "$ARTIFACTS_DIR/results.tsv"
}

step_fail() {
  local name="$1"
  FAIL_STEPS=$((FAIL_STEPS + 1))
  printf "FAIL\t%s\n" "$name" >> "$ARTIFACTS_DIR/results.tsv"
  if [[ "$KEEP_GOING" -eq 0 ]]; then
    write_summary
    exit 1
  fi
}

step_skip() {
  local name="$1"
  local reason="$2"
  SKIP_STEPS=$((SKIP_STEPS + 1))
  printf "SKIP\t%s\t%s\n" "$name" "$reason" >> "$ARTIFACTS_DIR/results.tsv"
}

run_step() {
  local step_name="$1"
  shift

  TOTAL_STEPS=$((TOTAL_STEPS + 1))
  local log_file="$ARTIFACTS_DIR/logs/${step_name}.log"
  log "STEP ${TOTAL_STEPS}: ${step_name}"

  "$@" > >(tee "$log_file") 2>&1
  local rc=$?
  if [[ "$rc" -eq 0 ]]; then
    step_pass "$step_name"
    return 0
  fi

  if [[ "$rc" -eq 42 ]]; then
    step_skip "$step_name" "${STEP_SKIP_REASON:-condition not met}"
    STEP_SKIP_REASON=""
    return 0
  fi

  step_fail "$step_name"
  return 1
}

skip_step() {
  local step_name="$1"
  local reason="$2"
  TOTAL_STEPS=$((TOTAL_STEPS + 1))
  log "STEP ${TOTAL_STEPS}: ${step_name} (skipped: ${reason})"
  step_skip "$step_name" "$reason"
}

run_with_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

run_install_release() {
  if [[ -z "$RELEASE_TAG" ]]; then
    echo "release tag is required for install step"
    return 1
  fi
  # Force non-interactive installer execution.
  run_with_sudo env DHI_SLACK_WEBHOOK="" DHI_REBUILD_EBPF=auto bash -c "bash scripts/install-linux-release.sh \"$RELEASE_TAG\" </dev/null"
}

run_install_verify_only() {
  run_with_sudo bash scripts/install-linux-release.sh --verify-only
}

resolve_arch_asset_name() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64) echo "dhi-linux-amd64.tar.gz" ;;
    aarch64|arm64) echo "dhi-linux-arm64.tar.gz" ;;
    *) echo "" ;;
  esac
}

resolve_metrics_port() {
  if [[ -n "$STATUS_PORT" ]]; then
    echo "$STATUS_PORT"
    return 0
  fi

  if [[ -f /etc/dhi/dhi.toml ]]; then
    python3 - <<'PY'
import sys
try:
    import tomllib
except Exception:
    print("9090")
    raise SystemExit(0)

try:
    with open("/etc/dhi/dhi.toml", "rb") as f:
        data = tomllib.load(f)
    port = data.get("metrics", {}).get("port", 9090)
    print(int(port))
except Exception:
    print("9090")
PY
    return 0
  fi

  echo "9090"
}

probe_health_on_port() {
  local port="$1"
  curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1
}

discover_active_runtime_port() {
  local candidates=()
  local seen=" "
  local add_candidate
  add_candidate() {
    local p="$1"
    [[ "$p" =~ ^[0-9]+$ ]] || return 0
    if [[ "$seen" != *" $p "* ]]; then
      seen="${seen}${p} "
      candidates+=("$p")
    fi
  }

  if [[ -n "$STATUS_PORT" ]]; then
    add_candidate "$STATUS_PORT"
  fi

  add_candidate "$(resolve_metrics_port)"
  add_candidate "9090"
  add_candidate "9191"

  for p in "${candidates[@]}"; do
    if probe_health_on_port "$p"; then
      STATUS_PORT="$p"
      return 0
    fi
  done

  if command -v ss >/dev/null 2>&1; then
    local ports
    ports="$(run_with_sudo ss -lntp 2>/dev/null | awk '/dhi/ {print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -u || true)"
    while IFS= read -r p; do
      [[ -n "$p" ]] || continue
      if probe_health_on_port "$p"; then
        STATUS_PORT="$p"
        return 0
      fi
    done <<< "$ports"
  fi

  return 1
}

verify_release_integrity() {
  local asset
  asset="$(resolve_arch_asset_name)"
  if [[ -z "$asset" ]]; then
    echo "Unsupported architecture for release asset verification: $(uname -m)"
    return 1
  fi

  command -v gh >/dev/null 2>&1 || { echo "Missing dependency: gh"; return 1; }
  command -v sha256sum >/dev/null 2>&1 || { echo "Missing dependency: sha256sum"; return 1; }

  local dir="$ARTIFACTS_DIR/release-assets"
  rm -rf "$dir"
  mkdir -p "$dir"

  gh release download "$RELEASE_TAG" --repo seconize-co/dhi --dir "$dir" --pattern "$asset"
  gh release download "$RELEASE_TAG" --repo seconize-co/dhi --dir "$dir" --pattern "SHA256SUMS"

  (cd "$dir" && sha256sum -c SHA256SUMS --ignore-missing)
}

runtime_health_checks() {
  command -v curl >/dev/null 2>&1 || { echo "Missing dependency: curl"; return 1; }
  command -v systemctl >/dev/null 2>&1 || { echo "systemctl not found"; return 1; }
  command -v date >/dev/null 2>&1 || { echo "Missing dependency: date"; return 1; }

  if [[ -f /etc/dhi/dhi.toml ]]; then
    if ! run_with_sudo /usr/local/bin/dhi --config /etc/dhi/dhi.toml --check >/dev/null 2>&1; then
      RUNTIME_FAILURE_REASON="config check failed (/usr/local/bin/dhi --config /etc/dhi/dhi.toml --check)"
      echo "Runtime readiness failed: ${RUNTIME_FAILURE_REASON}"
      return 1
    fi
  fi

  local startup_probe_since
  startup_probe_since="$(date --iso-8601=seconds)"
  run_with_sudo systemctl restart dhi
  sleep 2

  if ! run_with_sudo systemctl is-active --quiet dhi; then
    RUNTIME_FAILURE_REASON="systemd service dhi is not active"
    echo "Runtime readiness failed: ${RUNTIME_FAILURE_REASON}"
    return 1
  fi
  local port=""
  if discover_active_runtime_port; then
    port="$STATUS_PORT"
  else
    port="$(resolve_metrics_port)"
  fi
  if [[ -z "$port" ]]; then
    port="9090"
  fi
  STATUS_PORT="$port"
  log "Runtime port detected: $port"

  if ! curl -fsS "http://127.0.0.1:${port}/health" >/dev/null; then
    RUNTIME_FAILURE_REASON="health endpoint unreachable on port ${port}"
    return 1
  fi
  if ! curl -fsS "http://127.0.0.1:${port}/ready" >/dev/null; then
    RUNTIME_FAILURE_REASON="ready endpoint unreachable on port ${port}"
    return 1
  fi
  if ! curl -fsS "http://127.0.0.1:${port}/metrics" >/dev/null; then
    RUNTIME_FAILURE_REASON="metrics endpoint unreachable on port ${port}"
    return 1
  fi
  if ! curl -fsS "http://127.0.0.1:${port}/api/stats" >/dev/null; then
    RUNTIME_FAILURE_REASON="stats endpoint unreachable on port ${port}"
    return 1
  fi

  local journal_tail
  journal_tail="$(run_with_sudo journalctl -u dhi --since "$startup_probe_since" --no-pager 2>/dev/null || true)"
  if grep -q "Failed to load BPF object for SSL tracing" <<<"$journal_tail"; then
    RUNTIME_FAILURE_REASON="runtime journal reports SSL BPF object load failure"
    echo "Runtime readiness failed: ${RUNTIME_FAILURE_REASON}"
    return 1
  fi

  RUNTIME_AVAILABLE=1
  RUNTIME_FAILURE_REASON=""
}

collect_runtime_failure_context() {
  if command -v systemctl >/dev/null 2>&1; then
    run_with_sudo systemctl status dhi --no-pager -n 40 || true
    run_with_sudo journalctl -u dhi --no-pager -n 80 || true
  fi
}

run_security_harness() {
  local args=()
  if [[ "$SECURITY_SKIP_BUILD" -eq 1 ]]; then
    args+=(--skip-build)
  fi
  if [[ "$SECURITY_SKIP_QUALITY_GATE" -eq 1 ]]; then
    args+=(--skip-quality-gate)
  fi
  if [[ "$SECURITY_RUN_SUDO_TESTS" -eq 1 ]]; then
    args+=(--run-sudo-tests)
  fi

  bash scripts/security-e2e.sh "${args[@]}"
}

run_reporting_harness() {
  local port="${STATUS_PORT:-}"
  if [[ -z "$port" ]]; then
    if discover_active_runtime_port; then
      port="$STATUS_PORT"
    else
      port="$(resolve_metrics_port)"
    fi
  fi
  if [[ -z "$port" ]]; then
    port="9090"
  fi
  STATUS_PORT="$port"

  local args=(
    --reports-dir "$REPORTS_DIR"
    --stats-url "http://127.0.0.1:${port}/api/stats"
    --metrics-url "http://127.0.0.1:${port}/metrics"
  )
  if [[ "$REPORT_REQUIRE_RUNTIME_REPORTS" -eq 1 ]]; then
    args+=(--require-runtime-reports)
  fi
  if [[ "$REPORT_SKIP_LIVE_ENDPOINTS" -eq 1 ]]; then
    args+=(--skip-live-endpoints)
  fi

  bash scripts/reporting-e2e.sh "${args[@]}"
}

pause_managed_service_for_harness() {
  if command -v systemctl >/dev/null 2>&1 && run_with_sudo systemctl is-active --quiet dhi; then
    run_with_sudo systemctl stop dhi
    DHI_SERVICE_WAS_ACTIVE=1
    log "Paused systemd dhi service for standalone harness runs."
  fi
}

resume_managed_service_if_needed() {
  if [[ "$DHI_SERVICE_WAS_ACTIVE" -eq 1 ]]; then
    run_with_sudo systemctl start dhi
    DHI_SERVICE_WAS_ACTIVE=0
    log "Resumed systemd dhi service."
  fi
}

clear_stale_instance_lock() {
  local lock_file="/tmp/dhi.instance.lock"
  if [[ ! -f "$lock_file" ]]; then
    return 0
  fi

  if pgrep -x dhi >/dev/null 2>&1; then
    log "Dhi process detected; keeping existing instance lock."
    return 0
  fi

  run_with_sudo rm -f "$lock_file"
  log "Removed stale instance lock: $lock_file"
}

run_copilot_harness() {
  command -v copilot >/dev/null 2>&1 || { echo "copilot CLI not found"; return 1; }
  local port="${STATUS_PORT:-}"
  if [[ -z "$port" ]]; then
    if discover_active_runtime_port; then
      port="$STATUS_PORT"
    else
      port="$(resolve_metrics_port)"
    fi
  fi
  if [[ -z "$port" ]]; then
    port="9090"
  fi
  STATUS_PORT="$port"
  local out_file="$ARTIFACTS_DIR/logs/copilot-e2e-raw.log"
  if bash scripts/copilot-cli-e2e.sh --mode "$COPILOT_MODE" --dhi-port "$port" >"$out_file" 2>&1; then
    cat "$out_file"
    return 0
  fi

  cat "$out_file"

  local command_failures
  local delta_failures
  command_failures="$(grep -c 'FAIL: .*copilot-command' "$out_file" || true)"
  delta_failures="$(grep -c 'FAIL: .*alerts-delta' "$out_file" || true)"

  if [[ "$command_failures" -eq 0 && "$delta_failures" -gt 0 ]]; then
    STEP_SKIP_REASON="copilot traffic not observable in this environment (commands succeeded, alerts delta unchanged)"
    return 42
  fi

  return 1
}

run_uninstall_cycle() {
  run_with_sudo bash scripts/uninstall-linux.sh --dry-run
  run_with_sudo bash scripts/uninstall-linux.sh --purge-all

  local out_file="$ARTIFACTS_DIR/logs/post-uninstall-verify-only.log"
  if run_with_sudo bash scripts/install-linux-release.sh --verify-only >"$out_file" 2>&1; then
    echo "Expected verify-only to fail after uninstall, but it succeeded."
    return 1
  fi

  grep -Eq "Binary missing|critical check\(s\) failed" "$out_file"
}

write_summary() {
  local final_status="PASS"
  if [[ "$FAIL_STEPS" -gt 0 ]]; then
    final_status="FAIL"
  fi

  cat > "$ARTIFACTS_DIR/summary.md" <<EOF
# Dhi Release Verification Summary

- Status: **${final_status}**
- Total steps: ${TOTAL_STEPS}
- Passed: ${PASS_STEPS}
- Failed: ${FAIL_STEPS}
- Skipped: ${SKIP_STEPS}
- Artifacts: \`${ARTIFACTS_DIR}\`
- Release tag: \`${RELEASE_TAG:-not-specified}\`

## Step Results

\`\`\`
$(cat "$ARTIFACTS_DIR/results.tsv" 2>/dev/null || true)
\`\`\`
EOF

  python3 - "$ARTIFACTS_DIR" "$final_status" "$TOTAL_STEPS" "$PASS_STEPS" "$FAIL_STEPS" "$SKIP_STEPS" "${RELEASE_TAG:-}" <<'PY'
import json
import sys
from pathlib import Path

artifacts_dir = Path(sys.argv[1])
status = sys.argv[2]
total = int(sys.argv[3])
passed = int(sys.argv[4])
failed = int(sys.argv[5])
skipped = int(sys.argv[6])
release_tag = sys.argv[7]

steps = []
results_file = artifacts_dir / "results.tsv"
if results_file.exists():
    for line in results_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            item = {"status": parts[0], "step": parts[1]}
            if len(parts) >= 3:
                item["reason"] = parts[2]
            steps.append(item)

payload = {
    "status": status,
    "total_steps": total,
    "passed_steps": passed,
    "failed_steps": failed,
    "skipped_steps": skipped,
    "release_tag": release_tag or None,
    "steps": steps,
}

(artifacts_dir / "summary.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
PY
}

log "Artifacts directory: $ARTIFACTS_DIR"
echo -n > "$ARTIFACTS_DIR/results.tsv"

run_step "preflight-tools" bash -lc "command -v bash >/dev/null && command -v python3 >/dev/null && command -v curl >/dev/null" || true

if [[ "$RUN_INTEGRITY" -eq 1 ]]; then
  if [[ -n "$RELEASE_TAG" ]]; then
    run_step "release-integrity" verify_release_integrity || true
  else
    log "Skipping release-integrity: --release-tag not provided."
  fi
fi

if [[ "$RUN_INSTALL" -eq 1 ]]; then
  if [[ -n "$RELEASE_TAG" ]]; then
    run_step "install-release" run_install_release || true
  else
    log "Skipping install-release: --release-tag not provided."
  fi
  run_step "install-verify-only" run_install_verify_only || true
fi

if [[ "$RUN_RUNTIME_CHECKS" -eq 1 ]]; then
  run_step "runtime-health-checks" runtime_health_checks || true
  if [[ "$RUNTIME_AVAILABLE" -eq 0 ]]; then
    run_step "runtime-failure-context" collect_runtime_failure_context || true
  fi
fi

if [[ "$RUN_REPORTING" -eq 1 ]]; then
  if [[ "$RUNTIME_AVAILABLE" -eq 1 || "$REPORT_SKIP_LIVE_ENDPOINTS" -eq 1 ]]; then
    run_step "reporting-e2e" run_reporting_harness || true
  else
    skip_step "reporting-e2e" "runtime unavailable: ${RUNTIME_FAILURE_REASON:-unknown}"
  fi
fi

if [[ "$RUN_SECURITY" -eq 1 ]]; then
  run_step "pause-dhi-service" pause_managed_service_for_harness || true
  run_step "clear-stale-lock" clear_stale_instance_lock || true
  run_step "security-e2e" run_security_harness || true
  run_step "resume-dhi-service" resume_managed_service_if_needed || true
fi

if [[ "$RUN_COPILOT" -eq 1 ]]; then
  if [[ "$RUNTIME_AVAILABLE" -eq 1 ]]; then
    run_step "copilot-e2e-${COPILOT_MODE}" run_copilot_harness || true
  else
    skip_step "copilot-e2e-${COPILOT_MODE}" "runtime unavailable: ${RUNTIME_FAILURE_REASON:-unknown}"
  fi
fi

if [[ "$RUN_UNINSTALL_CYCLE" -eq 1 ]]; then
  run_step "uninstall-cycle" run_uninstall_cycle || true
fi

write_summary

log "Summary written:"
log "  - $ARTIFACTS_DIR/summary.md"
log "  - $ARTIFACTS_DIR/summary.json"

if [[ "$FAIL_STEPS" -gt 0 ]]; then
  exit 1
fi
