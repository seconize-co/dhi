#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VECTORS_FILE="${VECTORS_FILE:-$ROOT_DIR/scripts/security-test-vectors.json}"
PROXY_PORT="${PROXY_PORT:-18080}"
MONITOR_PORT="${MONITOR_PORT:-19090}"
SKIP_BUILD=0
SKIP_QUALITY_GATE=0
RUN_SUDO_TESTS=0

usage() {
  cat <<'EOF'
Usage: scripts/security-e2e.sh [options]

Options:
  --skip-build           Skip cargo build --release
  --skip-quality-gate    Skip cargo test/clippy gate
  --run-sudo-tests       Run monitor mode checks with sudo (for eBPF path)
  --vectors-file PATH    Path to security-test-vectors.json
  -h, --help             Show help

Notes:
  - Uses synthetic-only attack payloads (no real PII/secrets).
  - Proxy checks validate blocking decisions by HTTP status code.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --skip-quality-gate)
      SKIP_QUALITY_GATE=1
      shift
      ;;
    --run-sudo-tests)
      RUN_SUDO_TESTS=1
      shift
      ;;
    --vectors-file)
      VECTORS_FILE="$2"
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

for dep in python3 cargo curl; do
  command -v "$dep" >/dev/null 2>&1 || { echo "Missing dependency: $dep" >&2; exit 2; }
done

[[ -f "$VECTORS_FILE" ]] || { echo "Vectors file not found: $VECTORS_FILE" >&2; exit 2; }

PROXY_PID=""
MONITOR_PID=""

cleanup() {
  if [[ -n "$PROXY_PID" ]]; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [[ -n "$MONITOR_PID" ]]; then
    kill "$MONITOR_PID" >/dev/null 2>&1 || true
    wait "$MONITOR_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "PASS: $1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "FAIL: $1"
}

assert_eq() {
  local got="$1"
  local expected="$2"
  local label="$3"
  if [[ "$got" == "$expected" ]]; then
    pass "$label (expected=$expected got=$got)"
  else
    fail "$label (expected=$expected got=$got)"
  fi
}

echo "== Dhi Security E2E Harness =="
echo "Vectors: $VECTORS_FILE"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "== Build gate =="
  cargo build --release
else
  echo "== Build gate skipped =="
fi

if [[ "$SKIP_QUALITY_GATE" -eq 0 ]]; then
  echo "== Quality gate (tests + clippy) =="
  cargo test --all-features
  cargo clippy --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used
else
  echo "== Quality gate skipped =="
fi

echo "== Proxy security checks =="
./target/release/dhi --level block proxy --port "$PROXY_PORT" --block-secrets --block-pii > /tmp/dhi-proxy-e2e.log 2>&1 &
PROXY_PID=$!
sleep 2
if ! kill -0 "$PROXY_PID" >/dev/null 2>&1; then
  echo "Proxy failed to start. Last logs:"
  tail -n 40 /tmp/dhi-proxy-e2e.log || true
  exit 1
fi

mapfile -t TEST_LINES < <(python3 - "$VECTORS_FILE" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
for t in data.get("proxy_tests", []):
    kind = t.get("kind", "")
    if kind == "proxy_http":
        print(
            "\t".join([
                t["id"], kind, t["method"], t["path"], t["host"],
                str(t["expected_status"]), t["body"]
            ])
        )
    elif kind == "proxy_connect":
        print("\t".join([t["id"], kind, t["target"], str(t["expected_status"])]))
PY
)

for line in "${TEST_LINES[@]}"; do
  IFS=$'\t' read -r id kind a b c d e <<< "$line"
  if [[ "$kind" == "proxy_http" ]]; then
    method="$a"
    path="$b"
    host="$c"
    expected="$d"
    body="$e"
    status="$(curl -sS -o /tmp/dhi-e2e-body.out -w '%{http_code}' \
      -x "http://127.0.0.1:${PROXY_PORT}" \
      -X "$method" \
      "http://${host}${path}" \
      -H "Host: ${host}" \
      -H "Content-Type: application/json" \
      --data "$body" || true)"
    assert_eq "$status" "$expected" "$id"
  else
    target="$a"
    expected="$b"
    status="$(python3 - "$PROXY_PORT" "$target" <<'PY'
import socket
import sys

proxy_port = int(sys.argv[1])
target = sys.argv[2]
sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("utf-8")
sock.sendall(req)
resp = sock.recv(1024).decode("utf-8", errors="ignore")
sock.close()
first = resp.splitlines()[0] if resp else ""
parts = first.split()
print(parts[1] if len(parts) >= 2 else "000")
PY
)"
    assert_eq "$status" "$expected" "$id"
  fi
done

kill "$PROXY_PID" >/dev/null 2>&1 || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""

echo "== Demo sanity check =="
if ./target/release/dhi demo > /tmp/dhi-demo-e2e.log 2>&1; then
  if grep -Eq "ALERT|allowed: false|Context injection detected: true" /tmp/dhi-demo-e2e.log; then
    pass "demo-security-signals"
  else
    fail "demo-security-signals (expected alert/block markers not found)"
  fi
else
  fail "demo-command-execution"
fi

echo "== Monitor endpoint checks =="
if [[ "$RUN_SUDO_TESTS" -eq 1 ]]; then
  sudo ./target/release/dhi --level alert --port "$MONITOR_PORT" > /tmp/dhi-monitor-e2e.log 2>&1 &
  MONITOR_PID=$!
else
  ./target/release/dhi --level alert --port "$MONITOR_PORT" --no-ebpf > /tmp/dhi-monitor-e2e.log 2>&1 &
  MONITOR_PID=$!
fi
sleep 2
if kill -0 "$MONITOR_PID" >/dev/null 2>&1; then
  health_status="$(curl -sS -o /tmp/dhi-health.out -w '%{http_code}' "http://127.0.0.1:${MONITOR_PORT}/health" || true)"
  metrics_status="$(curl -sS -o /tmp/dhi-metrics.out -w '%{http_code}' "http://127.0.0.1:${MONITOR_PORT}/metrics" || true)"
  assert_eq "$health_status" "200" "monitor-health-endpoint"
  assert_eq "$metrics_status" "200" "monitor-metrics-endpoint"
else
  fail "monitor-startup"
fi

kill "$MONITOR_PID" >/dev/null 2>&1 || true
wait "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

echo "== Summary =="
echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
