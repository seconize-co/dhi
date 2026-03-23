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
#   ./scripts/dhi-health-check.sh --config /etc/dhi/dhi.toml
#   ./scripts/dhi-health-check.sh --service dhi --restart-on-fail

HEALTH_URL=""
HEALTH_URL_EXPLICIT=0
CONFIG_PATH="${DHI_CONFIG:-/etc/dhi/dhi.toml}"
HEALTH_SCHEME="${DHI_HEALTH_SCHEME:-http}"
HEALTH_PATH="${DHI_HEALTH_PATH:-/health}"
DEFAULT_HEALTH_HOST="${DHI_HEALTH_HOST:-127.0.0.1}"
DEFAULT_HEALTH_PORT="${DHI_HEALTH_PORT:-9090}"
SERVICE_NAME="dhi"
CURL_TIMEOUT=5
RESTART_ON_FAIL=0
CHECK_SYSTEMD=1
FAILURES_BEFORE_RESTART=3
RESTART_COOLDOWN_SEC=600
STATE_DIR="/run/dhi-health-check"

CONSEC_FAILS=0
LAST_RESTART_EPOCH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      HEALTH_URL="$2"
      HEALTH_URL_EXPLICIT=1
      shift 2
      ;;
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --health-scheme)
      HEALTH_SCHEME="$2"
      shift 2
      ;;
    --health-path)
      HEALTH_PATH="$2"
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
    --failures-before-restart)
      FAILURES_BEFORE_RESTART="$2"
      shift 2
      ;;
    --restart-cooldown)
      RESTART_COOLDOWN_SEC="$2"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="$2"
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
  --url <url>              Health endpoint URL (overrides TOML metrics settings)
  --config <path>          Dhi config path (default: /etc/dhi/dhi.toml or DHI_CONFIG)
  --health-scheme <value>  Endpoint scheme when deriving URL (default: http)
  --health-path <path>     Endpoint path when deriving URL (default: /health)
  --service <name>         Systemd service name (default: dhi)
  --timeout <seconds>      Curl timeout in seconds (default: 5)
  --failures-before-restart <n>
                           Restart only after n consecutive failures (default: 3)
  --restart-cooldown <seconds>
                           Minimum interval between restarts (default: 600)
  --state-dir <path>       Directory for lock/state files (default: /run/dhi-health-check)
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

validate_numeric_options() {
  local valid=1

  if [[ ! "$CURL_TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$CURL_TIMEOUT" -eq 0 ]]; then
    echo "Invalid --timeout value: $CURL_TIMEOUT" >&2
    valid=0
  fi

  if [[ ! "$FAILURES_BEFORE_RESTART" =~ ^[0-9]+$ ]] || [[ "$FAILURES_BEFORE_RESTART" -eq 0 ]]; then
    echo "Invalid --failures-before-restart value: $FAILURES_BEFORE_RESTART" >&2
    valid=0
  fi

  if [[ ! "$RESTART_COOLDOWN_SEC" =~ ^[0-9]+$ ]]; then
    echo "Invalid --restart-cooldown value: $RESTART_COOLDOWN_SEC" >&2
    valid=0
  fi

  if [[ "$valid" -ne 1 ]]; then
    exit 2
  fi
}

normalize_health_endpoint_parts() {
  if [[ -z "$HEALTH_SCHEME" ]]; then
    HEALTH_SCHEME="http"
  fi

  if [[ -z "$HEALTH_PATH" ]]; then
    HEALTH_PATH="/health"
  fi

  if [[ "${HEALTH_PATH:0:1}" != "/" ]]; then
    HEALTH_PATH="/${HEALTH_PATH}"
  fi
}

acquire_lock() {
  local lock_dir="$STATE_DIR/lock"
  mkdir -p "$STATE_DIR"

  if mkdir "$lock_dir" 2>/dev/null; then
    trap 'rmdir "$lock_dir" 2>/dev/null || true' EXIT
    return 0
  fi

  log "WARN: another health-check run is in progress; skipping"
  exit 0
}

load_state() {
  local state_file="$STATE_DIR/state.env"

  CONSEC_FAILS=0
  LAST_RESTART_EPOCH=0

  if [[ ! -f "$state_file" ]]; then
    return 0
  fi

  while IFS='=' read -r key value; do
    case "$key" in
      CONSEC_FAILS)
        if [[ "$value" =~ ^[0-9]+$ ]]; then
          CONSEC_FAILS="$value"
        fi
        ;;
      LAST_RESTART_EPOCH)
        if [[ "$value" =~ ^[0-9]+$ ]]; then
          LAST_RESTART_EPOCH="$value"
        fi
        ;;
    esac
  done < "$state_file"
}

save_state() {
  local state_file="$STATE_DIR/state.env"
  cat > "$state_file" <<EOF
CONSEC_FAILS=${CONSEC_FAILS}
LAST_RESTART_EPOCH=${LAST_RESTART_EPOCH}
EOF
}

toml_get_metrics_value() {
  local key="$1"
  local file="$2"

  awk -v key="$key" '
    /^[[:space:]]*\[/ {
      in_metrics = ($0 ~ /^[[:space:]]*\[metrics\][[:space:]]*$/)
      next
    }
    in_metrics && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      line = $0
      sub(/#.*/, "", line)
      sub(/^[^=]*=[[:space:]]*/, "", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      gsub(/^"|"$/, "", line)
      print line
      exit
    }
  ' "$file"
}

derive_health_url_from_config() {
  local bind="$DEFAULT_HEALTH_HOST"
  local port="$DEFAULT_HEALTH_PORT"
  local configured_bind=""
  local configured_port=""

  if [[ ! -f "$CONFIG_PATH" ]]; then
    log "WARN: config not found at $CONFIG_PATH, using default health URL"
    HEALTH_URL="${HEALTH_SCHEME}://${bind}:${port}${HEALTH_PATH}"
    return 0
  fi

  configured_bind="$(toml_get_metrics_value bind_address "$CONFIG_PATH" || true)"
  configured_port="$(toml_get_metrics_value port "$CONFIG_PATH" || true)"

  if [[ -n "$configured_bind" ]]; then
    bind="$configured_bind"
  fi

  if [[ "$bind" == "0.0.0.0" ]]; then
    # For local health checks use loopback when service binds all interfaces.
    bind="127.0.0.1"
  fi

  if [[ -n "$configured_port" && "$configured_port" =~ ^[0-9]+$ ]]; then
    port="$configured_port"
  fi

  HEALTH_URL="${HEALTH_SCHEME}://${bind}:${port}${HEALTH_PATH}"
  log "INFO: derived health URL from config (${CONFIG_PATH}): ${HEALTH_URL}"
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

should_restart_now() {
  local now
  local elapsed

  if [[ "$CONSEC_FAILS" -lt "$FAILURES_BEFORE_RESTART" ]]; then
    log "INFO: restart deferred (${CONSEC_FAILS}/${FAILURES_BEFORE_RESTART} consecutive failures)"
    return 1
  fi

  now="$(date +%s)"
  elapsed=$((now - LAST_RESTART_EPOCH))
  if [[ "$LAST_RESTART_EPOCH" -gt 0 && "$elapsed" -lt "$RESTART_COOLDOWN_SEC" ]]; then
    log "INFO: restart deferred by cooldown (${elapsed}s < ${RESTART_COOLDOWN_SEC}s)"
    return 1
  fi

  return 0
}

main() {
  local failed=0

  validate_numeric_options
  normalize_health_endpoint_parts
  acquire_lock
  load_state

  if [[ "$HEALTH_URL_EXPLICIT" -eq 0 ]]; then
    derive_health_url_from_config
  fi

  check_service_active || failed=1
  check_health_endpoint || failed=1

  if [[ "$failed" -eq 0 ]]; then
    CONSEC_FAILS=0
    save_state
    log "SUMMARY: healthy"
    exit 0
  fi

  CONSEC_FAILS=$((CONSEC_FAILS + 1))

  if [[ "$RESTART_ON_FAIL" -eq 1 ]]; then
    if should_restart_now; then
      if restart_service; then
        LAST_RESTART_EPOCH="$(date +%s)"
        CONSEC_FAILS=0
      fi
    fi
  fi

  save_state

  log "SUMMARY: unhealthy"
  exit 1
}

main
