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
TMP_DIR="${TMP_DIR:-/tmp/log/dhi/tmp}"

PASS_COUNT=0
FAIL_COUNT=0

usage() {
  cat <<'EOF'
Usage: scripts/copilot-cli-e2e.sh [options]

Options:
  --mode MODE                 Expected Dhi mode: alert|block (default: alert)
  --vectors-file PATH         Path to copilot-test-vectors.json
  --dhi-port PORT             Dhi metrics/api port (default: 9090)
  --run-id ID                 Correlation id inserted into prompts
  --dhi-log-file PATH         Optional Dhi log file path for regex assertions
  --tmp-dir PATH              Temp directory for prompt/output files (default: /tmp/log/dhi/tmp)
  --sleep-after-prompt SEC    Wait between prompt execution and stats check (default: 2)
  --copilot-run-template CMD  Copilot command template containing {prompt_file}
  -h, --help                  Show help

Examples:
  scripts/copilot-cli-e2e.sh --mode alert \
    --copilot-run-template 'copilot chat --prompt-file "{prompt_file}"'

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

if [[ "$COPILOT_RUN_TEMPLATE" != *"{prompt_file}"* ]]; then
  echo "--copilot-run-template must contain {prompt_file}" >&2
  exit 2
fi

mkdir -p "$TMP_DIR"

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

  prompt_file="$(mktemp "$TMP_DIR/dhi-copilot-prompt-${id}-XXXX.txt")"
  output_file="$(mktemp "$TMP_DIR/dhi-copilot-output-${id}-XXXX.log")"
  printf '%s\n' "$prompt" > "$prompt_file"

  cmd="${COPILOT_RUN_TEMPLATE//\{prompt_file\}/$prompt_file}"
  if bash -lc "$cmd" > "$output_file" 2>&1; then
    pass "${id}-copilot-command"
  else
    fail "${id}-copilot-command"
  fi

  sleep "$SLEEP_AFTER_PROMPT_SEC"

  rm -f "$prompt_file" "$output_file"
}

echo "== Dhi Copilot CLI E2E Harness =="
echo "Mode: $MODE"
echo "Vectors: $VECTORS_FILE"
echo "Run ID: $RUN_ID"

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
    prompt = t.get("prompt", "").replace("__RUN_ID__", run_id)
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

  IFS=$'\t' read -r before_alerts before_blocked <<< "$(get_stats)"
  execute_prompt "$id" "$prompt"
  IFS=$'\t' read -r after_alerts after_blocked <<< "$(get_stats)"

  delta_alerts=$((after_alerts - before_alerts))
  delta_blocked=$((after_blocked - before_blocked))

  if (( delta_alerts >= alerts_min )); then
    pass "${id}-alerts-delta (expected >= ${alerts_min}, got ${delta_alerts})"
  else
    fail "${id}-alerts-delta (expected >= ${alerts_min}, got ${delta_alerts})"
  fi

  if (( delta_blocked >= blocked_min )); then
    pass "${id}-blocked-delta (expected >= ${blocked_min}, got ${delta_blocked})"
  else
    fail "${id}-blocked-delta (expected >= ${blocked_min}, got ${delta_blocked})"
  fi

  if [[ -n "$regex" ]]; then
    if [[ -n "$DHI_LOG_FILE" && -f "$DHI_LOG_FILE" ]]; then
      if grep -E "$regex" "$DHI_LOG_FILE" >/dev/null 2>&1 && grep -F "RUN-${RUN_ID}" "$DHI_LOG_FILE" >/dev/null 2>&1; then
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
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
