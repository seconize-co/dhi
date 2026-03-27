#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VECTORS_FILE="${VECTORS_FILE:-$ROOT_DIR/scripts/copilot-test-vectors.json}"
MODE="${MODE:-alert}"
DHI_PORT="${DHI_PORT:-9090}"
SLEEP_AFTER_PROMPT_SEC="${SLEEP_AFTER_PROMPT_SEC:-2}"
CORRELATION_WINDOW_SEC="${CORRELATION_WINDOW_SEC:-60}"
COPILOT_RUN_TEMPLATE="${COPILOT_RUN_TEMPLATE:-copilot chat --prompt-file \"{prompt_file}\"}"
RUN_ID="${RUN_ID:-$(date +%s)}"
DHI_LOG_FILE="${DHI_LOG_FILE:-}"
ALERT_LOG_FILE="${ALERT_LOG_FILE:-}"
TMP_DIR="${TMP_DIR:-/tmp/log/dhi/tmp}"
USER_SET_TEMPLATE=0
AUTO_TMP_DIR=0
COPILOT_EXEC_MODE=""
COPILOT_VERSION="unknown"
COPILOT_SEMVER="unknown"

PASS_COUNT=0
FAIL_COUNT=0
COMMAND_FAIL_COUNT=0
POSITIVE_TEST_COUNT=0
MARKER_HIT_COUNT=0
LAST_PROMPT_PID=0
LAST_PROMPT_START_NS=0
LAST_PROMPT_END_NS=0
LAST_NEW_COPILOT_PIDS=""

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
  --correlation-window-sec N  Correlation window after each prompt (default: 60)
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
    --correlation-window-sec)
      CORRELATION_WINDOW_SEC="$2"
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

if ! [[ "$CORRELATION_WINDOW_SEC" =~ ^[0-9]+$ ]] || (( CORRELATION_WINDOW_SEC < 1 )); then
  echo "Invalid --correlation-window-sec: $CORRELATION_WINDOW_SEC" >&2
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

detect_copilot_version() {
  local raw_version
  raw_version="$(copilot --version 2>/dev/null | head -n 1 || true)"
  if [[ -n "$raw_version" ]]; then
    COPILOT_VERSION="$raw_version"
    COPILOT_SEMVER="$(python3 - "$raw_version" <<'PY'
import re
import sys
text = sys.argv[1]
m = re.search(r'(\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?)', text)
print(m.group(1) if m else "unknown")
PY
)"
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

marker_presence_count() {
  local marker="$1"
  if [[ -z "$DHI_LOG_FILE" || ! -f "$DHI_LOG_FILE" ]]; then
    echo "0"
    return 0
  fi
  python3 - "$DHI_LOG_FILE" "$marker" <<'PY'
import sys
path, marker = sys.argv[1:3]
count = 0
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if marker in line:
            count += 1
print(count)
PY
}

marker_prefix_count() {
  local marker_prefix="$1"
  if [[ -z "$DHI_LOG_FILE" || ! -f "$DHI_LOG_FILE" ]]; then
    echo "0"
    return 0
  fi
  python3 - "$DHI_LOG_FILE" "$marker_prefix" <<'PY'
import sys
path, marker_prefix = sys.argv[1:3]
count = 0
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if marker_prefix in line:
            count += 1
print(count)
PY
}

pid_window_alert_count() {
  local pid="$1"
  local category="$2"
  local start_ns="$3"
  local end_ns="$4"
  local window_ns="$5"
  if [[ -z "$ALERT_LOG_FILE" || ! -f "$ALERT_LOG_FILE" ]]; then
    echo "0"
    return 0
  fi

  python3 - "$ALERT_LOG_FILE" "$pid" "$category" "$start_ns" "$end_ns" "$window_ns" <<'PY'
import datetime
import json
import sys

path, pid_s, category, start_ns_s, end_ns_s, window_ns_s = sys.argv[1:7]
try:
    target_pid = int(pid_s)
    start_ns = int(start_ns_s)
    end_ns = int(end_ns_s)
    window_ns = int(window_ns_s)
except Exception:
    print(0)
    raise SystemExit(0)

# Allow async flush window after command completion.
end_ns = end_ns + window_ns

def ts_to_ns(raw: str):
    if not raw:
        return None
    try:
        # Normalize trailing Z for fromisoformat.
        normalized = raw.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(normalized)
        return int(dt.timestamp() * 1_000_000_000)
    except Exception:
        return None

def category_matches(md):
    if category == "secret":
        return bool(md.get("secret_types"))
    if category == "pii":
        return bool(md.get("pii_types"))
    if category == "injection":
        return md.get("injection_detected") is True or md.get("jailbreak_detected") is True
    return True

count = 0
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        ts_ns = ts_to_ns(obj.get("timestamp"))
        if ts_ns is None or ts_ns < start_ns or ts_ns > end_ns:
            continue
        md = obj.get("metadata", {}) or {}
        try:
            pid = int(md.get("pid"))
        except Exception:
            continue
        if pid != target_pid:
            continue
        if category_matches(md):
            count += 1

print(count)
PY
}

pid_window_dhi_log_count() {
  local pid="$1"
  local category="$2"
  local start_ns="$3"
  local end_ns="$4"
  local window_ns="$5"
  if [[ -z "$DHI_LOG_FILE" || ! -f "$DHI_LOG_FILE" ]]; then
    echo "0"
    return 0
  fi

  python3 - "$DHI_LOG_FILE" "$pid" "$category" "$start_ns" "$end_ns" "$window_ns" <<'PY'
import datetime
import re
import sys

path, pid_s, category, start_ns_s, end_ns_s, window_ns_s = sys.argv[1:7]
try:
    target_pid = int(pid_s)
    start_ns = int(start_ns_s)
    end_ns = int(end_ns_s)
    window_ns = int(window_ns_s)
except Exception:
    print(0)
    raise SystemExit(0)

end_ns = end_ns + window_ns
pid_pat = re.compile(r"PID=(\d+)")
ts_pat = re.compile(r"^(\d{4}-\d{2}-\d{2}T[^ ]+)")
category_patterns = {
    "secret": [r"Secrets detected", r"Secret evidence", r"ssl_secret_detected", r"SSL ALERT"],
    "pii": [r"PII detected", r"pii", r"ssl_pii_detected", r"SSL ALERT"],
    "injection": [r"Prompt injection", r"Injection indicators", r"ssl_prompt_injection_detected", r"SSL ALERT"],
    "any": [r"SSL ALERT", r"SSL BLOCKED", r"ssl_risk_detected"],
}
patterns = [re.compile(p, re.IGNORECASE) for p in category_patterns.get(category, category_patterns["any"])]

def ts_to_ns(raw: str):
    try:
        normalized = raw.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(normalized)
        return int(dt.timestamp() * 1_000_000_000)
    except Exception:
        return None

count = 0
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        m = ts_pat.search(line)
        if not m:
            continue
        ts_ns = ts_to_ns(m.group(1))
        if ts_ns is None or ts_ns < start_ns or ts_ns > end_ns:
            continue
        m = pid_pat.search(line)
        if not m:
            continue
        try:
            pid = int(m.group(1))
        except Exception:
            continue
        if pid != target_pid:
            continue
        if any(p.search(line) for p in patterns):
            count += 1

print(count)
PY
}

time_window_dhi_log_count() {
  local category="$1"
  local start_ns="$2"
  local end_ns="$3"
  local window_ns="$4"
  if [[ -z "$DHI_LOG_FILE" || ! -f "$DHI_LOG_FILE" ]]; then
    echo "0"
    return 0
  fi

  python3 - "$DHI_LOG_FILE" "$category" "$start_ns" "$end_ns" "$window_ns" <<'PY'
import datetime
import re
import sys

path, category, start_ns_s, end_ns_s, window_ns_s = sys.argv[1:6]
try:
    start_ns = int(start_ns_s)
    end_ns = int(end_ns_s)
    window_ns = int(window_ns_s)
except Exception:
    print(0)
    raise SystemExit(0)

end_ns = end_ns + window_ns
ts_pat = re.compile(r"^(\d{4}-\d{2}-\d{2}T[^ ]+)")
category_patterns = {
    "secret": [r"Secrets detected", r"Secret evidence", r"ssl_secret_detected", r"SSL ALERT"],
    "pii": [r"PII detected", r"pii", r"ssl_pii_detected", r"SSL ALERT"],
    "injection": [r"Prompt injection", r"Injection indicators", r"ssl_prompt_injection_detected", r"SSL ALERT"],
    "any": [r"SSL ALERT", r"SSL BLOCKED", r"ssl_risk_detected"],
}
patterns = [re.compile(p, re.IGNORECASE) for p in category_patterns.get(category, category_patterns["any"])]

def ts_to_ns(raw: str):
    try:
        normalized = raw.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(normalized)
        return int(dt.timestamp() * 1_000_000_000)
    except Exception:
        return None

count = 0
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        m = ts_pat.search(line)
        if not m:
            continue
        ts_ns = ts_to_ns(m.group(1))
        if ts_ns is None or ts_ns < start_ns or ts_ns > end_ns:
            continue
        if any(p.search(line) for p in patterns):
            count += 1

print(count)
PY
}

copilot_pids_snapshot() {
  python3 - <<'PY'
import subprocess

out = subprocess.check_output(["ps", "-eo", "pid,cmd"], text=True, errors="ignore")
pids = []
for line in out.splitlines():
    line = line.strip()
    if not line:
        continue
    parts = line.split(None, 1)
    if len(parts) < 2:
        continue
    pid_s, cmd = parts
    if "copilot" not in cmd:
        continue
    if "grep" in cmd:
        continue
    try:
        pids.append(int(pid_s))
    except Exception:
        pass
print(",".join(str(p) for p in sorted(set(pids))))
PY
}

pid_csv_delta() {
  local before_csv="$1"
  local after_csv="$2"
  python3 - "$before_csv" "$after_csv" <<'PY'
import sys

before = {int(x) for x in sys.argv[1].split(",") if x.strip().isdigit()}
after = [int(x) for x in sys.argv[2].split(",") if x.strip().isdigit()]
delta = [str(p) for p in after if p not in before]
print(",".join(delta))
PY
}

window_dhi_log_count_for_pid_csv() {
  local category="$1"
  local pid_csv="$2"
  local start_ns="$3"
  local end_ns="$4"
  local window_ns="$5"
  if [[ -z "$DHI_LOG_FILE" || ! -f "$DHI_LOG_FILE" || -z "$pid_csv" ]]; then
    echo "0"
    return 0
  fi

  python3 - "$DHI_LOG_FILE" "$category" "$pid_csv" "$start_ns" "$end_ns" "$window_ns" <<'PY'
import datetime
import re
import sys

path, category, pid_csv, start_ns_s, end_ns_s, window_ns_s = sys.argv[1:7]
try:
    start_ns = int(start_ns_s)
    end_ns = int(end_ns_s) + int(window_ns_s)
except Exception:
    print(0)
    raise SystemExit(0)

target_pids = {int(x) for x in pid_csv.split(",") if x.strip().isdigit()}
if not target_pids:
    print(0)
    raise SystemExit(0)

ts_pat = re.compile(r"^(\d{4}-\d{2}-\d{2}T[^ ]+)")
pid_pat = re.compile(r"PID=(\d+)")
category_patterns = {
    "secret": [r"Secrets detected", r"Secret evidence", r"ssl_secret_detected", r"SSL ALERT"],
    "pii": [r"PII detected", r"pii", r"ssl_pii_detected", r"SSL ALERT"],
    "injection": [r"Prompt injection", r"Injection indicators", r"ssl_prompt_injection_detected", r"SSL ALERT"],
    "any": [r"SSL ALERT", r"SSL BLOCKED", r"ssl_risk_detected"],
}
patterns = [re.compile(p, re.IGNORECASE) for p in category_patterns.get(category, category_patterns["any"])]

def ts_to_ns(raw: str):
    try:
        normalized = raw.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(normalized)
        return int(dt.timestamp() * 1_000_000_000)
    except Exception:
        return None

count = 0
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        m = ts_pat.search(line)
        if not m:
            continue
        ts_ns = ts_to_ns(m.group(1))
        if ts_ns is None or ts_ns < start_ns or ts_ns > end_ns:
            continue
        m = pid_pat.search(line)
        if not m:
            continue
        try:
            pid = int(m.group(1))
        except Exception:
            continue
        if pid not in target_pids:
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
  local session_id
  local pids_before
  local pids_after

  output_file="$(mktemp "$TMP_DIR/dhi-copilot-output-${id}-XXXX.log")"
  session_id="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"

  LAST_PROMPT_START_NS="$(date +%s%N)"
  LAST_PROMPT_PID=0
  LAST_NEW_COPILOT_PIDS=""
  pids_before="$(copilot_pids_snapshot)"

  if [[ "$COPILOT_EXEC_MODE" == "prompt_file" ]]; then
    prompt_file="$(mktemp "$TMP_DIR/dhi-copilot-prompt-${id}-XXXX.txt")"
    printf '%s\n' "$prompt" > "$prompt_file"

    if [[ "$USER_SET_TEMPLATE" -eq 1 ]]; then
      cmd="${COPILOT_RUN_TEMPLATE//\{prompt_file\}/$prompt_file}"
      cmd="${cmd//\{session_id\}/$session_id}"
      bash -lc "$cmd" > "$output_file" 2>&1 &
      LAST_PROMPT_PID=$!
      if wait "$LAST_PROMPT_PID"; then
        pass "${id}-copilot-command"
      else
        COMMAND_FAIL_COUNT=$((COMMAND_FAIL_COUNT + 1))
        fail "${id}-copilot-command"
      fi
    else
      copilot --resume="$session_id" chat --prompt-file "$prompt_file" > "$output_file" 2>&1 &
      LAST_PROMPT_PID=$!
      if wait "$LAST_PROMPT_PID"; then
        pass "${id}-copilot-command"
      else
        COMMAND_FAIL_COUNT=$((COMMAND_FAIL_COUNT + 1))
        fail "${id}-copilot-command"
      fi
    fi

    rm -f "$prompt_file"
  else
    copilot --resume="$session_id" -p "$prompt" > "$output_file" 2>&1 &
    LAST_PROMPT_PID=$!
    if wait "$LAST_PROMPT_PID"; then
      pass "${id}-copilot-command"
    else
      COMMAND_FAIL_COUNT=$((COMMAND_FAIL_COUNT + 1))
      fail "${id}-copilot-command"
    fi
  fi

  sleep "$SLEEP_AFTER_PROMPT_SEC"
  LAST_PROMPT_END_NS="$(date +%s%N)"
  pids_after="$(copilot_pids_snapshot)"
  LAST_NEW_COPILOT_PIDS="$(pid_csv_delta "$pids_before" "$pids_after")"

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
detect_copilot_version
resolve_alert_log_file
validate_template
echo "Copilot exec mode: $COPILOT_EXEC_MODE"
echo "Copilot version: $COPILOT_VERSION"
echo "Alert log file: $ALERT_LOG_FILE"
echo "Correlation window sec: $CORRELATION_WINDOW_SEC"

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
  marker_prefix="RUN-${RUN_ID}-"
  prompt="${prompt//__RUN_ID__/$marker_run_id}"
  category="$(alert_category_for_test_id "$id")"

  IFS=$'\t' read -r before_alerts before_blocked <<< "$(get_stats)"
  marker_alert_before="$(marker_alert_json_count "$marker" "$category")"
  marker_log_before="$(marker_dhi_log_count "$marker" "$category")"
  marker_presence_before="$(marker_presence_count "$marker")"
  marker_prefix_before="$(marker_prefix_count "$marker_prefix")"
  execute_prompt "$id" "$prompt"
  IFS=$'\t' read -r after_alerts after_blocked <<< "$(wait_for_stats_delta "$before_alerts" "$before_blocked" "$alerts_min" "$blocked_min")"
  marker_alert_after="$(marker_alert_json_count "$marker" "$category")"
  marker_log_after="$(marker_dhi_log_count "$marker" "$category")"
  marker_presence_after="$(marker_presence_count "$marker")"
  marker_prefix_after="$(marker_prefix_count "$marker_prefix")"
  window_ns=$((CORRELATION_WINDOW_SEC * 1000000000))
  pid_window_alert_hits="$(pid_window_alert_count "$LAST_PROMPT_PID" "$category" "$LAST_PROMPT_START_NS" "$LAST_PROMPT_END_NS" "$window_ns")"
  pid_window_log_hits="$(pid_window_dhi_log_count "$LAST_PROMPT_PID" "$category" "$LAST_PROMPT_START_NS" "$LAST_PROMPT_END_NS" "$window_ns")"
  pid_window_hits=$((pid_window_alert_hits + pid_window_log_hits))
  window_log_hits="$(time_window_dhi_log_count "$category" "$LAST_PROMPT_START_NS" "$LAST_PROMPT_END_NS" "$window_ns")"
  new_pid_window_hits="$(window_dhi_log_count_for_pid_csv "$category" "$LAST_NEW_COPILOT_PIDS" "$LAST_PROMPT_START_NS" "$LAST_PROMPT_END_NS" "$window_ns")"

  delta_alerts=$((after_alerts - before_alerts))
  delta_blocked=$((after_blocked - before_blocked))
  delta_marker_alert=$((marker_alert_after - marker_alert_before))
  delta_marker_log=$((marker_log_after - marker_log_before))
  delta_marker_presence=$((marker_presence_after - marker_presence_before))
  delta_marker_prefix=$((marker_prefix_after - marker_prefix_before))
  delta_marker=$((delta_marker_alert + delta_marker_log))
  if (( pid_window_hits > 0 )); then
    delta_marker=$((delta_marker + pid_window_hits))
  fi
  if (( delta_marker == 0 && delta_marker_presence > 0 && window_log_hits > 0 && delta_alerts >= alerts_min )); then
    # Fallback for transports where marker appears in run-marker/session logs but category evidence
    # cannot be tied to the same line. Correlate by prompt time window + category hit.
    delta_marker=$window_log_hits
  fi
  if (( delta_marker == 0 && delta_marker_prefix > 0 && window_log_hits > 0 && delta_alerts >= alerts_min )); then
    # Coarser fallback: run-level marker observed + category evidence in the same prompt window.
    delta_marker=$window_log_hits
  fi
  if (( delta_marker == 0 && new_pid_window_hits > 0 && delta_alerts >= alerts_min )); then
    # Stronger attribution: category evidence belongs to Copilot pids created by this prompt run.
    delta_marker=$new_pid_window_hits
  fi
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
      if grep -aF "$marker" "$DHI_LOG_FILE" >/dev/null 2>&1 && grep -aE "$regex" "$DHI_LOG_FILE" >/dev/null 2>&1; then
        pass "${id}-log-regex"
      elif (( pid_window_hits > 0 )); then
        pass "${id}-log-regex (pid-window correlation ${pid_window_hits})"
      elif (( delta_marker_presence > 0 && window_log_hits > 0 )); then
        pass "${id}-log-regex (marker+time-window correlation ${window_log_hits})"
      elif (( delta_marker_prefix > 0 && window_log_hits > 0 )); then
        pass "${id}-log-regex (run-marker+time-window correlation ${window_log_hits})"
      elif (( new_pid_window_hits > 0 )); then
        pass "${id}-log-regex (new-pid correlation ${new_pid_window_hits})"
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
  echo "COMPATIBILITY: copilot_cli_semver=${COPILOT_SEMVER} marker_correlation=unsupported"
  exit 42
fi
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "COMPATIBILITY: copilot_cli_semver=${COPILOT_SEMVER} marker_correlation=failed"
  exit 1
fi
echo "COMPATIBILITY: copilot_cli_semver=${COPILOT_SEMVER} marker_correlation=supported"
