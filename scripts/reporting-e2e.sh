#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VECTORS_FILE="${VECTORS_FILE:-$ROOT_DIR/scripts/report-test-vectors.json}"
REPORTS_DIR="${REPORTS_DIR:-/tmp/log/dhi/reports}"
STATS_URL="${STATS_URL:-http://127.0.0.1:9090/api/stats}"
METRICS_URL="${METRICS_URL:-http://127.0.0.1:9090/metrics}"
REQUIRE_RUNTIME_REPORTS=0
SKIP_LIVE_ENDPOINTS=0
SKIP_HTML_REPORT=0

PASS_COUNT=0
FAIL_COUNT=0

usage() {
  cat <<'EOF'
Usage: scripts/reporting-e2e.sh [options]

Options:
  --vectors-file PATH        Path to report-test-vectors.json
  --reports-dir PATH         Runtime reports directory (default: /tmp/log/dhi/reports)
  --stats-url URL            Stats endpoint (default: http://127.0.0.1:9090/api/stats)
  --metrics-url URL          Metrics endpoint (default: http://127.0.0.1:9090/metrics)
  --require-runtime-reports  Fail if no runtime JSON reports are found in reports dir
  --skip-live-endpoints      Skip /api/stats and /metrics checks
  --skip-html-report         Skip daily HTML report generation smoke check
  -h, --help                 Show help

What this validates:
  1) Sample report schema contracts (daily + agent analysis)
  2) Runtime report JSON files in reports dir (if present)
  3) Live reporting endpoints (/api/stats, /metrics) unless skipped
  4) Daily HTML report generation from JSON (unless skipped)

Note: Slack integration payload testing is intentionally excluded.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vectors-file)
      VECTORS_FILE="$2"
      shift 2
      ;;
    --reports-dir)
      REPORTS_DIR="$2"
      shift 2
      ;;
    --stats-url)
      STATS_URL="$2"
      shift 2
      ;;
    --metrics-url)
      METRICS_URL="$2"
      shift 2
      ;;
    --require-runtime-reports)
      REQUIRE_RUNTIME_REPORTS=1
      shift
      ;;
    --skip-live-endpoints)
      SKIP_LIVE_ENDPOINTS=1
      shift
      ;;
    --skip-html-report)
      SKIP_HTML_REPORT=1
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

for dep in python3 curl bash; do
  command -v "$dep" >/dev/null 2>&1 || { echo "Missing dependency: $dep" >&2; exit 2; }
done

[[ -f "$VECTORS_FILE" ]] || { echo "Vectors file not found: $VECTORS_FILE" >&2; exit 2; }

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "PASS: $1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "FAIL: $1"
}

validate_schema_tests() {
  mapfile -t schema_lines < <(python3 - "$VECTORS_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

for t in data.get("schema_tests", []):
    print("\t".join([
        t.get("id", ""),
        t.get("file", ""),
        t.get("report_type", ""),
        json.dumps(t.get("required_top_level", [])),
        json.dumps(t.get("required_summary_keys", [])),
    ]))
PY
  )

  for line in "${schema_lines[@]}"; do
    IFS=$'\t' read -r id rel_file report_type top_level_json summary_json <<< "$line"
    if [[ -z "$id" || -z "$rel_file" ]]; then
      continue
    fi

    full_file="$ROOT_DIR/$rel_file"
    if [[ ! -f "$full_file" ]]; then
      fail "${id}-file-exists"
      continue
    fi

    if python3 - "$full_file" "$report_type" "$top_level_json" "$summary_json" <<'PY'
import json
import sys

path = sys.argv[1]
expected_type = sys.argv[2]
required_top = json.loads(sys.argv[3])
required_summary = json.loads(sys.argv[4])

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

if data.get("report_type") != expected_type:
    raise SystemExit(1)

for k in required_top:
    if k not in data:
        raise SystemExit(1)

summary = data.get("summary")
if not isinstance(summary, dict):
    raise SystemExit(1)
for k in required_summary:
    if k not in summary:
        raise SystemExit(1)
PY
    then
      pass "${id}-schema"
    else
      fail "${id}-schema"
    fi
  done
}

validate_runtime_reports() {
  if [[ ! -d "$REPORTS_DIR" ]]; then
    if [[ "$REQUIRE_RUNTIME_REPORTS" -eq 1 ]]; then
      fail "runtime-reports-dir-exists"
    else
      echo "WARN: runtime reports dir not found: $REPORTS_DIR"
    fi
    return
  fi

  mapfile -t runtime_reports < <(find "$REPORTS_DIR" -maxdepth 1 -type f -name '*.json' 2>/dev/null | sort)
  if [[ "${#runtime_reports[@]}" -eq 0 ]]; then
    if [[ "$REQUIRE_RUNTIME_REPORTS" -eq 1 ]]; then
      fail "runtime-reports-present"
    else
      echo "WARN: no runtime report JSON files found in $REPORTS_DIR"
    fi
    return
  fi

  pass "runtime-reports-present (${#runtime_reports[@]} files)"

  for report_file in "${runtime_reports[@]}"; do
    if python3 - "$report_file" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

if "report_type" not in data:
    raise SystemExit(1)
if "generated_at" not in data:
    raise SystemExit(1)

rt = data.get("report_type")
if rt == "security_summary":
    if "summary" not in data or "alerts_by_type" not in data:
        raise SystemExit(1)
elif rt == "agent_analysis":
    if "summary" not in data or "agents" not in data:
        raise SystemExit(1)
PY
    then
      pass "runtime-schema-$(basename "$report_file")"
    else
      fail "runtime-schema-$(basename "$report_file")"
    fi
  done
}

validate_live_endpoints() {
  if [[ "$SKIP_LIVE_ENDPOINTS" -eq 1 ]]; then
    echo "WARN: live endpoint checks skipped"
    return
  fi

  stats_status="$(curl -sS -o /tmp/dhi-report-stats.out -w '%{http_code}' "$STATS_URL" || true)"
  metrics_status="$(curl -sS -o /tmp/dhi-report-metrics.out -w '%{http_code}' "$METRICS_URL" || true)"

  if [[ "$stats_status" == "200" ]]; then
    pass "reporting-stats-endpoint"
  else
    fail "reporting-stats-endpoint (expected=200 got=$stats_status)"
  fi

  if [[ "$metrics_status" == "200" ]]; then
    pass "reporting-metrics-endpoint"
  else
    fail "reporting-metrics-endpoint (expected=200 got=$metrics_status)"
  fi

  if python3 - /tmp/dhi-report-stats.out <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

required = ["llm_calls", "tool_calls", "alerts", "blocked"]
for key in required:
    if key not in data:
        raise SystemExit(1)
PY
  then
    pass "reporting-stats-schema"
  else
    fail "reporting-stats-schema"
  fi

  if grep -Eq '^dhi_(llm_calls_total|tool_calls_total|blocked_total|secrets_detected_total)' /tmp/dhi-report-metrics.out; then
    pass "reporting-metrics-keys"
  else
    fail "reporting-metrics-keys"
  fi
}

validate_html_report_generation() {
  if [[ "$SKIP_HTML_REPORT" -eq 1 ]]; then
    echo "WARN: html report generation check skipped"
    return
  fi

  local out_html="/tmp/dhi-sample-daily-report.html"
  rm -f "$out_html"

  if cargo run --quiet -- report-html --input examples/sample-report-daily.json --output "$out_html" --company Seconize >/tmp/dhi-report-html.out 2>/tmp/dhi-report-html.err; then
    pass "reporting-html-generate-command"
  else
    fail "reporting-html-generate-command"
    echo "---- report-html stderr ----"
    cat /tmp/dhi-report-html.err || true
    return
  fi

  if [[ -f "$out_html" ]]; then
    pass "reporting-html-output-exists"
  else
    fail "reporting-html-output-exists"
    return
  fi

  if grep -q "Executive Summary" "$out_html" && grep -q "All Alerts (Human Readable)" "$out_html" && grep -q "daily-report-json" "$out_html"; then
    pass "reporting-html-structure"
  else
    fail "reporting-html-structure"
  fi
}

echo "== Dhi Reporting E2E Harness =="
echo "Vectors: $VECTORS_FILE"
echo "Reports dir: $REPORTS_DIR"

echo "== Validate sample report schemas =="
validate_schema_tests

echo "== Validate runtime report artifacts =="
validate_runtime_reports

echo "== Validate reporting endpoints =="
validate_live_endpoints

echo "== Validate daily HTML report generation =="
validate_html_report_generation

echo "== Summary =="
echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
