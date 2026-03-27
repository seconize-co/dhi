#!/usr/bin/env bash
set -euo pipefail

# Generate a daily Dhi JSON/HTML report from live runtime endpoints.
#
# Usage:
#   dhi-generate-report
#   dhi-generate-report --config /etc/dhi/dhi.toml
#   dhi-generate-report --output-dir /var/log/dhi/reports

CONFIG_PATH="${DHI_CONFIG:-/etc/dhi/dhi.toml}"
OUTPUT_DIR=""
TIMEOUT_SECS="${DHI_REPORT_TIMEOUT:-15}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECS="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Generate a daily Dhi JSON/HTML report from live runtime endpoints.

Options:
  --config <path>      Config file path (default: /etc/dhi/dhi.toml)
  --output-dir <path>  Override report output directory
  --timeout <seconds>  HTTP timeout for endpoint calls (default: 15)
  -h, --help           Show this help
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! "$TIMEOUT_SECS" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT_SECS" -eq 0 ]]; then
  echo "Invalid timeout value: $TIMEOUT_SECS" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi
if ! command -v dhi >/dev/null 2>&1; then
  echo "dhi binary is required to render HTML report" >&2
  exit 1
fi

readarray -t CFG_VALUES < <(python3 - "$CONFIG_PATH" <<'PY'
import json
import sys

cfg_path = sys.argv[1]
default = {
    "output_dir": "/var/log/dhi/reports",
    "company_name": "Seconize",
    "bind_address": "127.0.0.1",
    "port": 9090,
}

try:
    import tomllib
except Exception:
    print(default["output_dir"])
    print(default["company_name"])
    print(default["bind_address"])
    print(default["port"])
    raise SystemExit(0)

try:
    with open(cfg_path, "rb") as f:
        data = tomllib.load(f)
except Exception:
    data = {}

reporting = data.get("reporting", {}) if isinstance(data, dict) else {}
metrics = data.get("metrics", {}) if isinstance(data, dict) else {}

output_dir = reporting.get("output_dir") or default["output_dir"]
company = reporting.get("company_name") or default["company_name"]
bind_address = metrics.get("bind_address") or default["bind_address"]
port = metrics.get("port") or default["port"]

if bind_address in ("0.0.0.0", "::"):
    bind_address = "127.0.0.1"

print(str(output_dir))
print(str(company))
print(str(bind_address))
print(str(port))
PY
)

REPORT_DIR="${OUTPUT_DIR:-${CFG_VALUES[0]:-/var/log/dhi/reports}}"
COMPANY_NAME="${CFG_VALUES[1]:-Seconize}"
METRICS_HOST="${CFG_VALUES[2]:-127.0.0.1}"
METRICS_PORT="${CFG_VALUES[3]:-9090}"

mkdir -p "$REPORT_DIR"
umask 0027

today_utc="$(date -u +%Y-%m-%d)"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
json_out="${REPORT_DIR}/daily-${today_utc}.json"
html_out="${REPORT_DIR}/daily-${today_utc}.html"
tmp_json="$(mktemp "${REPORT_DIR}/.daily-${today_utc}.json.tmp.XXXXXX")"
tmp_stats="$(mktemp)"
tmp_agents="$(mktemp)"
trap 'rm -f "$tmp_json" "$tmp_stats" "$tmp_agents"' EXIT

base_url="http://${METRICS_HOST}:${METRICS_PORT}"
curl -fsS --max-time "$TIMEOUT_SECS" "${base_url}/api/stats" -o "$tmp_stats"
curl -fsS --max-time "$TIMEOUT_SECS" "${base_url}/api/agents" -o "$tmp_agents"

python3 - "$tmp_stats" "$tmp_agents" "$generated_at" "$COMPANY_NAME" "$json_out" "$tmp_json" <<'PY'
import json
import os
import platform
import sys
from datetime import datetime, timedelta, timezone

stats_path, agents_path, generated_at, company_name, out_path, tmp_path = sys.argv[1:7]

with open(stats_path, "r", encoding="utf-8") as f:
    stats = json.load(f)
with open(agents_path, "r", encoding="utf-8") as f:
    agents = json.load(f)

generated_dt = datetime.now(timezone.utc)
start_dt = (generated_dt - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
end_dt = generated_dt.replace(hour=0, minute=0, second=0, microsecond=0)

alerts_total = int(stats.get("alerts", 0) or 0)
blocked_total = int(stats.get("blocked", 0) or 0)
llm_calls = int(stats.get("llm_calls", 0) or 0)
tool_calls = int(stats.get("tool_calls", 0) or 0)
total_agents = int(agents.get("total_agents", 0) or 0)

alerts_by_type = {}
if alerts_total > 0:
    alerts_by_type["ssl_risk_detected"] = alerts_total

alerts_by_severity = {
    "critical": 0,
    "high": 0,
    "medium": alerts_total,
    "low": 0,
}

report = {
    "report_type": "security_summary",
    "generated_at": generated_at,
    "period": {
        "start": start_dt.isoformat().replace("+00:00", "Z"),
        "end": end_dt.isoformat().replace("+00:00", "Z"),
    },
    "source": "dhi-generate-report",
    "company_name": company_name,
    "hostname": platform.node(),
    "summary": {
        "total_agents": total_agents,
        "total_llm_calls": llm_calls,
        "total_tool_calls": tool_calls,
        "total_cost_usd": 0.0,
        "total_alerts": alerts_total,
        "total_blocks": blocked_total,
    },
    "alerts_by_severity": alerts_by_severity,
    "alerts_by_type": alerts_by_type,
    "top_risk_agents": [],
    "secrets_detected": [],
    "pii_detected": [],
    "injection_attempts": [],
    "dangerous_tool_calls": [],
    "cost_breakdown": {
        "by_provider": {},
        "by_model": {},
        "by_agent": {},
    },
    "efficiency_metrics": {
        "duplicate_prompts": 0,
        "similar_prompts": 0,
        "tool_loops_detected": 0,
        "estimated_waste_usd": 0.0,
        "efficiency_score": 100,
    },
    "recommendations": [],
    "stats": stats,
    "agents_report": agents,
}

with open(tmp_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
os.replace(tmp_path, out_path)
PY

dhi report-html --input "$json_out" --output "$html_out" --company "$COMPANY_NAME" >/dev/null
if [[ ! -s "$html_out" ]]; then
  echo "failed to generate HTML report: $html_out" >&2
  exit 1
fi

echo "Generated daily report: $json_out"
echo "Generated daily HTML report: $html_out"
