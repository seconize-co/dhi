#!/usr/bin/env bash
set -euo pipefail

# Dhi health checker for cron/systemd-timer automation.
#
# Default behavior:
# - checks Dhi health via native `dhi health` when available
# - falls back to direct health endpoint curl check
# - verifies systemd service is active (when systemctl is available)
# - exits 0 on success, 1 on failure
#
# Optional behavior:
# - restart service on failure with --restart-on-fail
#
# Usage:
#   ./scripts/dhi-health-check.sh
#   ./scripts/dhi-health-check.sh --url http://127.0.0.1:9090/health
#   ./scripts/dhi-health-check.sh --service dhi --restart-on-fail

HEALTH_URL="http://127.0.0.1:9090/health"
SERVICE_NAME="dhi"
CURL_TIMEOUT=5
RESTART_ON_FAIL=0
CHECK_SYSTEMD=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      HEALTH_URL="$2"
      shift 2
      ;;
    --service)
      SERVICE_NAME="$2"
      shift 2
      ;;
    --timeout)
      CURL_TIMEOUT="$2"
      shift 2
      ;;
    --restart-on-fail)
      RESTART_ON_FAIL=1
      shift
      ;;
    --no-systemd-check)
      CHECK_SYSTEMD=0
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Dhi health checker

Options:
  --url <url>              Health endpoint URL (default: http://127.0.0.1:9090/health)
  --service <name>         Systemd service name (default: dhi)
  --timeout <seconds>      Curl timeout in seconds (default: 5)
  --restart-on-fail        Restart service if checks fail
  --no-systemd-check       Skip systemd active-state check
  -h, --help               Show this help
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

log() {
  printf '%s %s\n' "[$(date '+%Y-%m-%d %H:%M:%S')]" "$*"
}

fail() {
  log "FAIL: $*"
  return 1
}

check_service_active() {
  if [[ "$CHECK_SYSTEMD" -eq 0 ]]; then
    return 0
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    log "WARN: systemctl not found; skipping service active check"
    return 0
  fi

  if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
    log "OK: service is active ($SERVICE_NAME)"
    return 0
  fi

  fail "service is not active ($SERVICE_NAME)"
}

check_health_endpoint() {
  local body

  if command -v dhi >/dev/null 2>&1 && dhi help health >/dev/null 2>&1; then
    if dhi health --url "$HEALTH_URL" --timeout "$CURL_TIMEOUT" >/dev/null 2>&1; then
      log "OK: native cli health check passed"
      return 0
    fi

    fail "native cli health check failed"
    return 1
  fi

  if ! body="$(curl -fsS --max-time "$CURL_TIMEOUT" "$HEALTH_URL")"; then
    fail "health endpoint unreachable ($HEALTH_URL)"
    return 1
  fi

  if grep -qi '"status"[[:space:]]*:[[:space:]]*"healthy"' <<<"$body"; then
    log "OK: health endpoint reports healthy"
    return 0
  fi

  fail "unexpected health response: $body"
}

restart_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    log "WARN: cannot restart service without systemctl"
    return 1
  fi

  log "ACTION: restarting service ($SERVICE_NAME)"
  sudo systemctl restart "$SERVICE_NAME"

  if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
    log "OK: service restarted successfully"
    return 0
  fi

  fail "service restart failed"
}

main() {
  local failed=0

  check_service_active || failed=1
  check_health_endpoint || failed=1

  if [[ "$failed" -eq 0 ]]; then
    log "SUMMARY: healthy"
    exit 0
  fi

  if [[ "$RESTART_ON_FAIL" -eq 1 ]]; then
    restart_service || true
  fi

  log "SUMMARY: unhealthy"
  exit 1
}

main
