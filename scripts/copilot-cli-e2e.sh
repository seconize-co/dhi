#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VECTORS_FILE="${VECTORS_FILE:-$ROOT_DIR/scripts/copilot-test-vectors.json}"
MODE="${MODE:-alert}"
DHI_PORT="${DHI_PORT:-9090}"
SLEEP_AFTER_PROMPT_SEC="${SLEEP_AFTER_PROMPT_SEC:-2}"
COPILOT_RUN_TEMPLATE="${COPILOT_RUN_TEMPLATE:-copilot chat --prompt-file \"{prompt_file}\"}"
RUN_ID="${RUN_ID:-$(date +%s)}"
DHI_LOG_FILE="${DHI_LOG_FILE:-}"
ALERT_LOG_FILE="${ALERT_LOG_FILE:-}"
TMP_DIR="${TMP_DIR:-/tmp/log/dhi/tmp}"
USER_SET_TEMPLATE=0
AUTO_TMP_DIR=0
COPILOT_EXEC_MODE=""

PASS_COUNT=0
FAIL_COUNT=0
COMMAND_FAIL_COUNT=0
POSITIVE_TEST_COUNT=0
MARKER_HIT_COUNT=0

usage() {
  cat <<'EOF'
Usage: scripts/copilot-cli-e2e.sh [options]

Options:
  --mode MODE                 Expected Dhi mode: alert|block (default: alert)
  --vectors-file PATH         Path to copilot-test-vectors.json
  --dhi-port PORT             Dhi metrics/api port (default: 9090)
  --run-id ID                 Correlation id inserted into prompts
  --dhi-log-file PATH         Optional Dhi log file path for regex assertions
  --alert-log-file PATH       Optional Dhi alert log file path for marker correlation checks
  --tmp-dir PATH              Temp directory for prompt/output files (default: /tmp/log/dhi/tmp)
  --sleep-after-prompt SEC    Wait between prompt execution and stats check (default: 2)
  --copilot-run-template CMD  Optional command template containing {prompt_file}
  -h, --help                  Show help

Examples:
  scripts/copilot-cli-e2e.sh --mode alert

  scripts/copilot-cli-e2e.sh --mode block --dhi-log-file /tmp/log/dhi/dhi.log \
    --copilot-run-template 'copilot chat --prompt-file "{prompt_file}"'

Notes:
  - Start Dhi separately before running this script.
  - Use synthetic data only.
  - For block mode with eBPF process actions (term/kill), use a disposable Copilot process/session.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --vectors-file)
      VECTORS_FILE="$2"
      shift 2
      ;;
    --dhi-port)
      DHI_PORT="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --dhi-log-file)
      DHI_LOG_FILE="$2"
      shift 2
      ;;
    --alert-log-file)
      ALERT_LOG_FILE="$2"
      shift 2
      ;;
    --tmp-dir)
      TMP_DIR="$2"
      shift 2
      ;;
    --sleep-after-prompt)
      SLEEP_AFTER_PROMPT_SEC="$2"
      shift 2
      ;;
    --copilot-run-template)
      COPILOT_RUN_TEMPLATE="$2"
      USER_SET_TEMPLATE=1
      shift 2
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

if [[ "$MODE" != "alert" && "$MODE" != "block" ]]; then
  echo "Invalid mode: $MODE (must be alert or block)" >&2
  exit 2
fi

for dep in python3 curl bash; do
  command -v "$dep" >/dev/null 2>&1 || { echo "Missing dependency: $dep" >&2; exit 2; }
done

if ! command -v copilot >/dev/null 2>&1; then
  echo "Missing dependency: copilot" >&2
  exit 2
fi

[[ -f "$VECTORS_FILE" ]] || { echo "Vectors file not found: $VECTORS_FILE" >&2; exit 2; }

if ! mkdir -p "$TMP_DIR" >/dev/null 2>&1 || [[ ! -w "$TMP_DIR" ]]; then
  TMP_DIR="$(mktemp -d /tmp/dhi-copilot-tmp-XXXX)"
  AUTO_TMP_DIR=1
  echo "WARN: Falling back to writable tmp dir: $TMP_DIR"
fi

cleanup() {
  if [[ "$AUTO_TMP_DIR" -eq 1 && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

detect_copilot_exec_mode() {
  local help_text

  help_text="$(copilot chat --help 2>&1 || true)"
  if [[ "$help_text" == *"--prompt-file"* ]]; then
    COPILOT_EXEC_MODE="prompt_file"
  else
    COPILOT_EXEC_MODE="prompt_inline"
  fi
}

resolve_alert_log_file() {
  if [[ -n "$ALERT_LOG_FILE" ]]; then
    return 0
  fi

  ALERT_LOG_FILE="$(python3 - "$ROOT_DIR" <<'PY'
import os
import sys
try:
    import tomllib
except Exception:
    print("/var/log/dhi/alerts.log")
    raise SystemExit(0)

root_dir = sys.argv[1]
candidates = [
    "/etc/dhi/dhi.toml",
    os.path.join(root_dir, "dhi.toml"),
]

for path in candidates:
    if not os.path.exists(path):
        continue
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        continue
    alerting = data.get("alerting", {}) if isinstance(data, dict) else {}
    out = alerting.get("alert_log_path")
    if isinstance(out, str) and out.strip():
        print(out.strip())
        raise SystemExit(0)

print("/var/log/dhi/alerts.log")
PY
)"
}

marker_alert_json_count() {
  local marker="$1"
  local category="$2"
  if [[ -z "$ALERT_LOG_FILE" || ! -f "$ALERT_LOG_FILE" ]]; then
    echo "0"
    return 0
  fi

  python3 - "$ALERT_LOG_FILE" "$marker" "$category" <<'PY'
import json
import sys

path, marker, category = sys.argv[1:4]
count = 0

with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if marker not in line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        md = obj.get("metadata", {}) or {}
        if category == "secret":
            if md.get("secret_types"):
                count += 1
        elif category == "pii":
            if md.get("pii_types"):
                count += 1
        elif category == "injection":
            if md.get("injection_detected") is True or md.get("jailbreak_detected") is True:
                count += 1
        else:
            count += 1

print(count)
PY
}

marker_dhi_log_count() {
  local marker="$1"
  local category="$2"
  if [[ -z "$DHI_LOG_FILE" || ! -f "$DHI_LOG_FILE" ]]; then
    echo "0"
    return 0
  fi

  python3 - "$DHI_LOG_FILE" "$marker" "$category" <<'PY'
import re
import sys

path, marker, category = sys.argv[1:4]
category_patterns = {
    "secret": [r"Secrets detected", r"secret_types", r"credential", r"SSL ALERT"],
    "pii": [r"PII", r"pii_types", r"credit card", r"SSN", r"SSL ALERT"],
    "injection": [r"Prompt injection", r"injection_detected", r"jailbreak_detected", r"SSL ALERT"],
    "any": [r"SSL ALERT", r"SSL BLOCKED", r"ssl_risk_detected"],
}
patterns = [re.compile(p, re.IGNORECASE) for p in category_patterns.get(category, category_patterns["any"])]

count = 0
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if marker not in line:
            continue
        if any(p.search(line) for p in patterns):
            count += 1
print(count)
PY
}

alert_category_for_test_id() {
  local id="$1"
  case "$id" in
    *secret*) echo "secret" ;;
    *pii*) echo "pii" ;;
    *inject*|*jailbreak*) echo "injection" ;;
    *) echo "any" ;;
  esac
}

validate_template() {
  if [[ "$USER_SET_TEMPLATE" -eq 0 ]]; then
    return 0
  fi

  if [[ "$COPILOT_RUN_TEMPLATE" != *"{prompt_file}"* ]]; then
    echo "--copilot-run-template must contain {prompt_file}" >&2
    exit 2
  fi
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "PASS: $1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "FAIL: $1"
}

get_stats() {
  python3 - "$DHI_PORT" <<'PY'
import json
import sys
import urllib.request

port = sys.argv[1]
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/stats", timeout=3) as r:
        data = json.loads(r.read().decode("utf-8", errors="ignore"))
except Exception:
    print("0\t0")
    sys.exit(0)

alerts = int(data.get("alerts", 0))
blocked = int(data.get("blocked", 0))
print(f"{alerts}\t{blocked}")
PY
}

execute_prompt() {
  local id="$1"
  local prompt="$2"
  local prompt_file
  local output_file
  local cmd

  output_file="$(mktemp "$TMP_DIR/dhi-copilot-output-${id}-XXXX.log")"

  if [[ "$COPILOT_EXEC_MODE" == "prompt_file" ]]; then
    prompt_file="$(mktemp "$TMP_DIR/dhi-copilot-prompt-${id}-XXXX.txt")"
    printf '%s\n' "$prompt" > "$prompt_file"

    if [[ "$USER_SET_TEMPLATE" -eq 1 ]]; then
      cmd="${COPILOT_RUN_TEMPLATE//\{prompt_file\}/$prompt_file}"
      if bash -lc "$cmd" > "$output_file" 2>&1; then
        pass "${id}-copilot-command"
      else
        COMMAND_FAIL_COUNT=$((COMMAND_FAIL_COUNT + 1))
        fail "${id}-copilot-command"
      fi
    else
      if copilot chat --prompt-file "$prompt_file" > "$output_file" 2>&1; then
        pass "${id}-copilot-command"
      else
        COMMAND_FAIL_COUNT=$((COMMAND_FAIL_COUNT + 1))
        fail "${id}-copilot-command"
      fi
    fi

    rm -f "$prompt_file"
  else
    if copilot -p "$prompt" > "$output_file" 2>&1; then
      pass "${id}-copilot-command"
    else
      COMMAND_FAIL_COUNT=$((COMMAND_FAIL_COUNT + 1))
      fail "${id}-copilot-command"
    fi
  fi

  sleep "$SLEEP_AFTER_PROMPT_SEC"

  rm -f "$output_file"
}

wait_for_stats_delta() {
  local before_alerts="$1"
  local before_blocked="$2"
  local expected_alerts="$3"
  local expected_blocked="$4"
  local after_alerts="$before_alerts"
  local after_blocked="$before_blocked"

  # Allow asynchronous SSL processing to flush into /api/stats.
  for _ in 1 2 3 4 5 6; do
    IFS=$'\t' read -r after_alerts after_blocked <<< "$(get_stats)"
    local delta_alerts=$((after_alerts - before_alerts))
    local delta_blocked=$((after_blocked - before_blocked))
    if (( delta_alerts >= expected_alerts && delta_blocked >= expected_blocked )); then
      break
    fi
    sleep 1
  done

  printf '%s\t%s\n' "$after_alerts" "$after_blocked"
}

echo "== Dhi Copilot CLI E2E Harness =="
echo "Mode: $MODE"
echo "Vectors: $VECTORS_FILE"
echo "Run ID: $RUN_ID"
detect_copilot_exec_mode
resolve_alert_log_file
validate_template
echo "Copilot exec mode: $COPILOT_EXEC_MODE"
echo "Alert log file: $ALERT_LOG_FILE"

mapfile -t TEST_LINES < <(python3 - "$VECTORS_FILE" "$MODE" "$RUN_ID" <<'PY'
import json
import sys

path = sys.argv[1]
mode = sys.argv[2]
run_id = sys.argv[3]

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

for t in data.get("copilot_tests", []):
    exp = t.get("expected_delta", {}).get(mode, {})
    prompt = t.get("prompt", "")
    alerts_min = int(exp.get("alerts_min", 0))
    blocked_min = int(exp.get("blocked_min", 0))
    regex = t.get("require_log_regex", "")
    print("\t".join([t.get("id", ""), prompt, str(alerts_min), str(blocked_min), regex]))
PY
)

for line in "${TEST_LINES[@]}"; do
  IFS=$'\t' read -r id prompt alerts_min blocked_min regex <<< "$line"
  if [[ -z "$id" ]]; then
    continue
  fi

  marker_run_id="${RUN_ID}-${id}"
  marker="RUN-${marker_run_id}"
  prompt="${prompt//__RUN_ID__/$marker_run_id}"
  category="$(alert_category_for_test_id "$id")"

  IFS=$'\t' read -r before_alerts before_blocked <<< "$(get_stats)"
  marker_alert_before="$(marker_alert_json_count "$marker" "$category")"
  marker_log_before="$(marker_dhi_log_count "$marker" "$category")"
  execute_prompt "$id" "$prompt"
  IFS=$'\t' read -r after_alerts after_blocked <<< "$(wait_for_stats_delta "$before_alerts" "$before_blocked" "$alerts_min" "$blocked_min")"
  marker_alert_after="$(marker_alert_json_count "$marker" "$category")"
  marker_log_after="$(marker_dhi_log_count "$marker" "$category")"

  delta_alerts=$((after_alerts - before_alerts))
  delta_blocked=$((after_blocked - before_blocked))
  delta_marker_alert=$((marker_alert_after - marker_alert_before))
  delta_marker_log=$((marker_log_after - marker_log_before))
  delta_marker=$((delta_marker_alert + delta_marker_log))
  correlation_available=0
  if [[ -f "$ALERT_LOG_FILE" || ( -n "$DHI_LOG_FILE" && -f "$DHI_LOG_FILE" ) ]]; then
    correlation_available=1
  fi

  if (( alerts_min == 0 )); then
    pass "${id}-alerts-delta (expected >= 0, got ${delta_alerts})"
  elif (( correlation_available == 1 )); then
    POSITIVE_TEST_COUNT=$((POSITIVE_TEST_COUNT + 1))
    if (( delta_marker >= alerts_min )); then
      MARKER_HIT_COUNT=$((MARKER_HIT_COUNT + 1))
      pass "${id}-alerts-delta (marker-correlated alerts ${delta_marker}; stats delta ${delta_alerts})"
    else
      fail "${id}-alerts-delta (expected marker-correlated >= ${alerts_min}, got ${delta_marker}; stats delta ${delta_alerts})"
    fi
  elif (( delta_alerts >= alerts_min )); then
    POSITIVE_TEST_COUNT=$((POSITIVE_TEST_COUNT + 1))
    pass "${id}-alerts-delta (expected >= ${alerts_min}, got ${delta_alerts}; correlation unavailable)"
  else
    POSITIVE_TEST_COUNT=$((POSITIVE_TEST_COUNT + 1))
    fail "${id}-alerts-delta (expected >= ${alerts_min}, got ${delta_alerts})"
  fi

  if (( delta_blocked >= blocked_min )); then
    pass "${id}-blocked-delta (expected >= ${blocked_min}, got ${delta_blocked})"
  else
    fail "${id}-blocked-delta (expected >= ${blocked_min}, got ${delta_blocked})"
  fi

  if [[ -n "$regex" ]]; then
    if [[ -n "$DHI_LOG_FILE" && -f "$DHI_LOG_FILE" ]]; then
      if grep -aE "$regex" "$DHI_LOG_FILE" >/dev/null 2>&1 && grep -aF "$marker" "$DHI_LOG_FILE" >/dev/null 2>&1; then
        pass "${id}-log-regex"
      else
        fail "${id}-log-regex"
      fi
    else
      echo "WARN: Skipping ${id}-log-regex (no --dhi-log-file provided)"
    fi
  fi
done

echo "== Summary =="
echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"
if (( FAIL_COUNT > 0 && COMMAND_FAIL_COUNT == 0 && POSITIVE_TEST_COUNT > 0 && MARKER_HIT_COUNT == 0 )); then
  echo "WARN: Copilot traffic not observable with marker correlation in this environment."
  exit 42
fi
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
