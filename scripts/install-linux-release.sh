#!/usr/bin/env bash
set -euo pipefail

# Install Dhi from GitHub Release artifacts (Linux only).
# Installs:
#   - /usr/local/bin/dhi
#   - /usr/share/dhi/dhi_ssl.bpf.o
#   - production log directories under /var/log/dhi
#   - logrotate policy for dhi logs/reports (best effort)
#
# Usage:
#   ./scripts/install-linux-release.sh v1.2.3
#   DHI_VERSION=v1.2.3 ./scripts/install-linux-release.sh
#
# Optional:
#   DHI_LOG_ROOT=/tmp/log/dhi DHI_VERSION=v1.2.3 ./scripts/install-linux-release.sh
#   --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL

REPO="seconize-co/dhi"
LOG_ROOT="${DHI_LOG_ROOT:-/var/log/dhi}"
ENABLE_HEALTH_TIMER="${DHI_ENABLE_HEALTH_TIMER:-1}"
SLACK_WEBHOOK="${DHI_SLACK_WEBHOOK:-}"
REBUILD_EBPF_MODE="${DHI_REBUILD_EBPF:-auto}" # auto | always | never
VERIFY_ONLY=0
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify-only)
      VERIFY_ONLY=1
      shift
      ;;
    --slack-webhook)
      SLACK_WEBHOOK="$2"
      shift 2
      ;;
    --rebuild-ebpf)
      REBUILD_EBPF_MODE="always"
      shift
      ;;
    --no-rebuild-ebpf)
      REBUILD_EBPF_MODE="never"
      shift
      ;;
    -h|--help)
      echo "Install Dhi from GitHub release artifacts (Linux only)."
      echo
      echo "Usage:"
      echo "  $0 <version-tag> [--slack-webhook <url>]"
      echo "  DHI_VERSION=<version-tag> $0"
      echo "  $0 --verify-only"
      echo
      echo "Options:"
      echo "  --slack-webhook <url>   Set Slack webhook URL in /etc/dhi/dhi.toml (optional)"
      echo "  --rebuild-ebpf          Rebuild eBPF object on this host (fail if rebuild fails)"
      echo "  --no-rebuild-ebpf       Skip host rebuild and keep bundled eBPF object"
      echo
      echo "Examples:"
      echo "  $0 v1.2.3"
      echo "  $0 v1.2.3 --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
      echo "  $0 v1.2.3 --rebuild-ebpf"
      echo "  DHI_REBUILD_EBPF=auto $0 v1.2.3"
      echo "  DHI_VERSION=v1.2.3 $0"
      echo "  $0 --verify-only"
      exit 0
      ;;
    --)
      shift
      POSITIONAL+=("$@")
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ "${#POSITIONAL[@]}" -gt 1 ]]; then
  echo "Too many positional arguments."
  echo "Usage: $0 <version-tag> | $0 --verify-only"
  exit 1
fi

RELEASE_VERSION="${POSITIONAL[0]:-${DHI_VERSION:-}}"

if [[ "$VERIFY_ONLY" -eq 0 && -z "$RELEASE_VERSION" ]]; then
  echo "Usage: $0 <version-tag>  (example: $0 v1.2.3)"
  echo "Or set DHI_VERSION=v1.2.3"
  echo "Or run verification only: $0 --verify-only"
  exit 1
fi

case "$REBUILD_EBPF_MODE" in
  auto|always|never) ;;
  *)
    echo "Invalid DHI_REBUILD_EBPF value: ${REBUILD_EBPF_MODE}"
    echo "Expected one of: auto, always, never"
    exit 1
    ;;
esac

if [[ "${OSTYPE:-}" != linux* ]]; then
  echo "This installer supports Linux only."
  exit 1
fi

OS_ID="unknown"
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
fi

INIT_MODEL="non-systemd"
if command -v systemctl >/dev/null 2>&1; then
  INIT_MODEL="systemd"
elif [[ "$OS_ID" == "alpine" ]]; then
  INIT_MODEL="openrc"
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ASSET="dhi-linux-amd64.tar.gz" ;;
  aarch64|arm64) ASSET="dhi-linux-arm64.tar.gz" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    echo "Supported: x86_64, aarch64/arm64"
    exit 1
    ;;
esac

URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${ASSET}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

install_logrotate_pkg() {
  if command -v logrotate >/dev/null 2>&1; then
    return 0
  fi

  echo "logrotate not found; attempting installation..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y logrotate
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y logrotate
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y logrotate
  elif command -v zypper >/dev/null 2>&1; then
    sudo zypper install -y logrotate
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm logrotate
  elif command -v apk >/dev/null 2>&1; then
    sudo apk add logrotate
  else
    echo "WARNING: Could not detect package manager to install logrotate."
    return 1
  fi

  command -v logrotate >/dev/null 2>&1
}

install_logrotate_policy() {
  local local_policy="ops/logrotate/dhi"
  local remote_policy="https://raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/ops/logrotate/dhi"
  local tmp_policy="$TMPDIR/dhi.logrotate"

  if [[ -f "$local_policy" ]]; then
    sudo install -m 644 "$local_policy" /etc/logrotate.d/dhi
    return 0
  fi

  if curl -fsSL "$remote_policy" -o "$tmp_policy"; then
    sudo install -m 644 "$tmp_policy" /etc/logrotate.d/dhi
    return 0
  fi

  echo "WARNING: Could not obtain logrotate policy file (local or remote)."
  return 1
}

check_rotation_scheduler() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^logrotate.timer'; then
    if systemctl is-enabled logrotate.timer >/dev/null 2>&1 || systemctl is-active logrotate.timer >/dev/null 2>&1; then
      echo "logrotate scheduler: systemd timer is enabled/active"
      return 0
    fi
    echo "WARNING: logrotate.timer exists but is not enabled/active."
    echo "         Run: sudo systemctl enable --now logrotate.timer"
    return 1
  fi

  if [[ -x /etc/cron.daily/logrotate ]]; then
    echo "logrotate scheduler: cron.daily script present"
    return 0
  fi

  echo "WARNING: No logrotate scheduler detected (systemd timer or cron.daily)."
  return 1
}

install_systemd_service() {
  local local_service="ops/systemd/dhi.service"
  local remote_service="https://raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/ops/systemd/dhi.service"
  local tmp_service="$TMPDIR/dhi.service"

  if [[ -f "$local_service" ]]; then
    sudo install -m 644 "$local_service" /etc/systemd/system/dhi.service
    return 0
  fi

  if curl -fsSL "$remote_service" -o "$tmp_service"; then
    sudo install -m 644 "$tmp_service" /etc/systemd/system/dhi.service
    return 0
  fi

  echo "WARNING: Could not obtain systemd service file (local or remote)."
  return 1
}

install_health_check_script() {
  local local_script="scripts/dhi-health-check.sh"
  local remote_script="https://raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/scripts/dhi-health-check.sh"
  local tmp_script="$TMPDIR/dhi-health-check.sh"

  if [[ -f "$local_script" ]]; then
    sudo install -m 755 "$local_script" /usr/local/bin/dhi-health-check
    return 0
  fi

  if curl -fsSL "$remote_script" -o "$tmp_script"; then
    sudo install -m 755 "$tmp_script" /usr/local/bin/dhi-health-check
    return 0
  fi

  echo "WARNING: Could not obtain health-check script (local or remote)."
  return 1
}

install_health_systemd_units() {
  local local_service="ops/systemd/dhi-health-check.service"
  local local_timer="ops/systemd/dhi-health-check.timer"
  local remote_service="https://raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/ops/systemd/dhi-health-check.service"
  local remote_timer="https://raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/ops/systemd/dhi-health-check.timer"
  local tmp_service="$TMPDIR/dhi-health-check.service"
  local tmp_timer="$TMPDIR/dhi-health-check.timer"

  if [[ -f "$local_service" && -f "$local_timer" ]]; then
    sudo install -m 644 "$local_service" /etc/systemd/system/dhi-health-check.service
    sudo install -m 644 "$local_timer" /etc/systemd/system/dhi-health-check.timer
    return 0
  fi

  if curl -fsSL "$remote_service" -o "$tmp_service" && curl -fsSL "$remote_timer" -o "$tmp_timer"; then
    sudo install -m 644 "$tmp_service" /etc/systemd/system/dhi-health-check.service
    sudo install -m 644 "$tmp_timer" /etc/systemd/system/dhi-health-check.timer
    return 0
  fi

  echo "WARNING: Could not obtain health-check systemd units (local or remote)."
  return 1
}

resolve_bpftool_bin() {
  local bpftool_bin=""
  bpftool_bin="$(find /usr/lib/linux-tools -type f -name bpftool 2>/dev/null | head -n 1 || true)"
  if [[ -z "$bpftool_bin" ]]; then
    bpftool_bin="$(command -v bpftool || true)"
  fi
  echo "$bpftool_bin"
}

target_arch_define() {
  case "$ARCH" in
    x86_64) echo "__TARGET_ARCH_x86" ;;
    aarch64|arm64) echo "__TARGET_ARCH_arm64" ;;
    *) return 1 ;;
  esac
}

rebuild_ebpf_object() {
  local source_c="$TMPDIR/dhi_ssl.bpf.c"
  local source_url="https://raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/bpf/dhi_ssl.bpf.c"
  local bpftool_bin=""
  local arch_define=""

  if ! command -v clang >/dev/null 2>&1; then
    echo "eBPF rebuild skipped: clang not found."
    return 2
  fi
  if [[ ! -f /usr/include/bpf/bpf_helpers.h ]]; then
    echo "eBPF rebuild skipped: libbpf headers missing (/usr/include/bpf/bpf_helpers.h)."
    return 2
  fi

  bpftool_bin="$(resolve_bpftool_bin)"
  if [[ -z "$bpftool_bin" ]]; then
    echo "eBPF rebuild skipped: bpftool not found."
    return 2
  fi
  if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    echo "eBPF rebuild skipped: /sys/kernel/btf/vmlinux not found."
    return 2
  fi

  if [[ -f "bpf/dhi_ssl.bpf.c" ]]; then
    cp "bpf/dhi_ssl.bpf.c" "$source_c"
  elif ! curl -fsSL "$source_url" -o "$source_c"; then
    echo "eBPF rebuild skipped: could not fetch source ${source_url}"
    return 2
  fi

  arch_define="$(target_arch_define || true)"
  if [[ -z "$arch_define" ]]; then
    echo "eBPF rebuild skipped: unsupported architecture for clang define (${ARCH})."
    return 2
  fi

  if ! "$bpftool_bin" btf dump file /sys/kernel/btf/vmlinux format c > "$TMPDIR/vmlinux.h"; then
    echo "eBPF rebuild failed: bpftool BTF dump error."
    return 1
  fi
  if ! clang -O2 -target bpf -D"${arch_define}" -I"$TMPDIR" -c "$source_c" -o "$TMPDIR/dhi_ssl.bpf.o"; then
    echo "eBPF rebuild failed: clang compilation error."
    return 1
  fi
  if ! test -s "$TMPDIR/dhi_ssl.bpf.o"; then
    echo "eBPF rebuild failed: output object missing."
    return 1
  fi
  if ! sudo install -m 644 "$TMPDIR/dhi_ssl.bpf.o" /usr/share/dhi/dhi_ssl.bpf.o; then
    echo "eBPF rebuild failed: could not install rebuilt object."
    return 1
  fi
  return 0
}

install_config_file() {
  if [[ ! -f "$TMPDIR/etc/dhi/dhi.toml.example" ]]; then
    echo "WARNING: Config template not found in release archive."
    return 1
  fi

  sudo install -d /etc/dhi
  
  # Install template
  sudo install -m 644 "$TMPDIR/etc/dhi/dhi.toml.example" /etc/dhi/dhi.toml.example

  # Install external pattern template when available.
  if [[ -f "$TMPDIR/etc/dhi/dhi.patterns.toml.example" ]]; then
    sudo install -m 644 "$TMPDIR/etc/dhi/dhi.patterns.toml.example" /etc/dhi/dhi.patterns.toml.example
  elif [[ -f "dhi.patterns.toml.example" ]]; then
    sudo install -m 644 "dhi.patterns.toml.example" /etc/dhi/dhi.patterns.toml.example
  else
    local remote_patterns="https://raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/dhi.patterns.toml.example"
    if ! curl -fsSL "$remote_patterns" -o "$TMPDIR/dhi.patterns.toml.example"; then
      echo "WARNING: Could not obtain dhi.patterns.toml.example (archive/local/remote)."
    else
      sudo install -m 644 "$TMPDIR/dhi.patterns.toml.example" /etc/dhi/dhi.patterns.toml.example
    fi
  fi
  
  # Create config only if it doesn't exist (preserve on upgrades)
  if [[ ! -f /etc/dhi/dhi.toml ]]; then
    sudo install -m 644 "$TMPDIR/etc/dhi/dhi.toml.example" /etc/dhi/dhi.toml
  fi

  # Create external pattern config only if it doesn't exist (preserve on upgrades).
  if [[ -f /etc/dhi/dhi.patterns.toml.example && ! -f /etc/dhi/dhi.patterns.toml ]]; then
    sudo install -m 644 /etc/dhi/dhi.patterns.toml.example /etc/dhi/dhi.patterns.toml
  fi
  
  return 0
}

print_non_systemd_guidance() {
  if [[ "$OS_ID" == "alpine" ]]; then
    echo "WARNING: Alpine detected (OpenRC); systemd service registration is skipped."
    echo "         Configure auto-start with OpenRC local service:"
    echo "         1) sudo tee /etc/local.d/dhi.start >/dev/null <<'EOF'"
    echo "            #!/bin/sh"
    echo "            exec /usr/local/bin/dhi --config /etc/dhi/dhi.toml --level alert"
    echo "            EOF"
    echo "         2) sudo chmod +x /etc/local.d/dhi.start"
    echo "         3) sudo rc-update add local default"
    echo "         4) sudo rc-service local start"
    echo "         Logs: check /var/log/messages or your configured Dhi log file."
  else
    echo "WARNING: systemd not detected; Dhi service will not be registered."
    echo "         You can still run Dhi manually: sudo dhi --config /etc/dhi/dhi.toml --level alert"
  fi
}

VERIFICATION_FAILURES=0
VERIFICATION_WARNINGS=0

verify_ok() {
  echo "[OK]   $1"
}

verify_warn() {
  echo "[WARN] $1"
  VERIFICATION_WARNINGS=$((VERIFICATION_WARNINGS + 1))
}

verify_fail() {
  echo "[FAIL] $1"
  VERIFICATION_FAILURES=$((VERIFICATION_FAILURES + 1))
}

verify_rotation_scheduler() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^logrotate.timer'; then
    if systemctl is-enabled logrotate.timer >/dev/null 2>&1 || systemctl is-active logrotate.timer >/dev/null 2>&1; then
      verify_ok "logrotate scheduler: systemd timer is enabled/active"
    else
      verify_warn "logrotate.timer exists but is not enabled/active"
    fi
    return
  fi

  if [[ -x /etc/cron.daily/logrotate ]]; then
    verify_ok "logrotate scheduler: cron.daily script present"
  else
    verify_warn "No logrotate scheduler detected (systemd timer or cron.daily)"
  fi
}

run_post_install_verification() {
  echo
  echo "Post-install verification"
  echo "-------------------------"

  if [[ -x /usr/local/bin/dhi ]]; then
    verify_ok "Binary installed: /usr/local/bin/dhi"
  else
    verify_fail "Binary missing or not executable: /usr/local/bin/dhi"
  fi

  if /usr/local/bin/dhi --version >/dev/null 2>&1; then
    verify_ok "Binary executable check passed (dhi --version)"
  else
    verify_fail "Binary executable check failed (dhi --version)"
  fi

  if [[ -f /usr/share/dhi/dhi_ssl.bpf.o ]]; then
    verify_ok "eBPF object installed: /usr/share/dhi/dhi_ssl.bpf.o"
  else
    verify_fail "eBPF object missing: /usr/share/dhi/dhi_ssl.bpf.o"
  fi

  if [[ -f /etc/dhi/dhi.toml.example ]]; then
    verify_ok "Config template installed: /etc/dhi/dhi.toml.example"
  else
    verify_warn "Config template missing: /etc/dhi/dhi.toml.example"
  fi

  if [[ -f /etc/dhi/dhi.toml ]]; then
    verify_ok "Config file present: /etc/dhi/dhi.toml"
  else
    verify_warn "Config file missing: /etc/dhi/dhi.toml"
  fi

  if [[ -f /etc/dhi/dhi.patterns.toml.example ]]; then
    verify_ok "Pattern template installed: /etc/dhi/dhi.patterns.toml.example"
  else
    verify_warn "Pattern template missing: /etc/dhi/dhi.patterns.toml.example"
  fi

  if [[ -f /etc/dhi/dhi.patterns.toml ]]; then
    verify_ok "Pattern config file present: /etc/dhi/dhi.patterns.toml"
  else
    verify_warn "Pattern config file missing: /etc/dhi/dhi.patterns.toml"
  fi

  if [[ -d "$LOG_ROOT" && -d "$LOG_ROOT/reports" ]]; then
    verify_ok "Log directories ready: ${LOG_ROOT}, ${LOG_ROOT}/reports"
  else
    verify_fail "Log directories missing under ${LOG_ROOT}"
  fi

  if command -v logrotate >/dev/null 2>&1; then
    if [[ -f /etc/logrotate.d/dhi ]]; then
      verify_ok "Logrotate policy installed: /etc/logrotate.d/dhi"
      if logrotate -d /etc/logrotate.d/dhi >/dev/null 2>&1; then
        verify_ok "Logrotate policy validation passed"
      else
        verify_warn "Logrotate policy validation failed"
      fi
      verify_rotation_scheduler
    else
      verify_warn "Logrotate installed but policy missing: /etc/logrotate.d/dhi"
    fi
  else
    verify_warn "logrotate not installed"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    if [[ -f /etc/systemd/system/dhi.service ]]; then
      verify_ok "Systemd unit installed: /etc/systemd/system/dhi.service"
    else
      verify_warn "Systemd unit missing: /etc/systemd/system/dhi.service"
    fi

    if systemctl is-enabled dhi >/dev/null 2>&1; then
      verify_ok "Systemd service enabled: dhi"
    else
      verify_warn "Systemd service not enabled: dhi"
    fi

    if [[ -x /usr/local/bin/dhi-health-check ]]; then
      verify_ok "Health-check script installed: /usr/local/bin/dhi-health-check"
    else
      verify_warn "Health-check script missing: /usr/local/bin/dhi-health-check"
    fi

    if [[ -f /etc/systemd/system/dhi-health-check.service ]]; then
      verify_ok "Health-check unit installed: /etc/systemd/system/dhi-health-check.service"
    else
      verify_warn "Health-check unit missing: /etc/systemd/system/dhi-health-check.service"
    fi

    if [[ -f /etc/systemd/system/dhi-health-check.timer ]]; then
      verify_ok "Health-check timer installed: /etc/systemd/system/dhi-health-check.timer"
    else
      verify_warn "Health-check timer missing: /etc/systemd/system/dhi-health-check.timer"
    fi

    if systemctl is-enabled dhi-health-check.timer >/dev/null 2>&1; then
      verify_ok "Health-check timer enabled: dhi-health-check.timer"
    else
      verify_warn "Health-check timer not enabled: dhi-health-check.timer"
    fi
  else
    if [[ "$OS_ID" == "alpine" ]]; then
      verify_warn "Alpine/OpenRC detected; systemd service registration skipped"
    else
      verify_warn "systemd not detected; service registration skipped"
    fi
  fi

  echo
  if [[ "$VERIFICATION_FAILURES" -eq 0 && "$VERIFICATION_WARNINGS" -eq 0 ]]; then
    echo "Installation verification summary: ALL OK"
  elif [[ "$VERIFICATION_FAILURES" -eq 0 ]]; then
    echo "Installation verification summary: OK with ${VERIFICATION_WARNINGS} warning(s)"
    echo "Review warning messages above for optional improvements."
  else
    echo "Installation verification summary: ${VERIFICATION_FAILURES} critical check(s) failed"
    echo "Please review messages above before using Dhi in production."
    return 1
  fi

  return 0
}

if [[ "$VERIFY_ONLY" -eq 1 ]]; then
  echo "Detected distro: ${OS_ID} (${INIT_MODEL} path)"
  echo "Running verification only (no install actions)."
  run_post_install_verification
  exit $?
fi

echo "Detected distro: ${OS_ID} (${INIT_MODEL} path)"

echo "Downloading ${URL}"
curl -fL "$URL" -o "$TMPDIR/$ASSET"

echo "Extracting ${ASSET}"
tar -xzf "$TMPDIR/$ASSET" -C "$TMPDIR"

if [[ ! -f "$TMPDIR/usr/local/bin/dhi" ]]; then
  echo "Expected binary not found in archive: usr/local/bin/dhi"
  exit 1
fi

if [[ ! -f "$TMPDIR/usr/share/dhi/dhi_ssl.bpf.o" ]]; then
  echo "Expected eBPF object not found in archive: usr/share/dhi/dhi_ssl.bpf.o"
  exit 1
fi

echo "Installing dhi to /usr/local/bin"
sudo install -m 755 "$TMPDIR/usr/local/bin/dhi" /usr/local/bin/dhi

echo "Installing eBPF object to /usr/share/dhi"
sudo install -d /usr/share/dhi
sudo install -m 644 "$TMPDIR/usr/share/dhi/dhi_ssl.bpf.o" /usr/share/dhi/dhi_ssl.bpf.o

if [[ "$REBUILD_EBPF_MODE" != "never" ]]; then
  echo "Attempting host eBPF rebuild (mode=${REBUILD_EBPF_MODE})..."
  if rebuild_ebpf_object; then
    echo "Host-built eBPF object installed to /usr/share/dhi/dhi_ssl.bpf.o"
  else
    if [[ "$REBUILD_EBPF_MODE" == "always" ]]; then
      echo "ERROR: eBPF rebuild required but failed."
      exit 1
    fi
    echo "WARNING: Host eBPF rebuild failed; continuing with bundled eBPF object."
  fi
fi

echo "Creating production log/report directories at ${LOG_ROOT}"
sudo install -d "$LOG_ROOT" "$LOG_ROOT/reports"

if install_config_file; then
  echo "Config files installed to /etc/dhi/"
fi

if [[ -z "$SLACK_WEBHOOK" ]] && [[ -t 0 ]]; then
  echo
  echo "Slack alerting (optional)"
  echo "  Dhi can send security alerts to a Slack channel via an Incoming Webhook."
  printf "  Enter your Slack webhook URL, or press Enter to skip: "
  read -r _input_webhook
  if [[ -n "$_input_webhook" ]]; then
    SLACK_WEBHOOK="$_input_webhook"
  else
    echo "  Skipped. You can set it later in /etc/dhi/dhi.toml under [alerting] slack_webhook."
  fi
  unset _input_webhook
fi

validate_slack_webhook() {
  local url="$1"

  # Format check: must be a https://hooks.slack.com/ URL
  if [[ ! "$url" =~ ^https://hooks\.slack\.com/ ]]; then
    echo "WARNING: Slack webhook URL does not look valid (expected https://hooks.slack.com/...)."
    return 1
  fi

  if ! command -v curl >/dev/null 2>&1; then
    echo "INFO: curl not found; skipping live Slack webhook test."
    return 0
  fi

  echo "Testing Slack webhook..."
  local http_code
  http_code="$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST -H 'Content-type: application/json' \
    --max-time 10 \
    --data '{"text":"Dhi installation test \u2013 Slack alerting is working."}' \
    "$url")"

  case "$http_code" in
    200)
      echo "Slack webhook test: OK (HTTP 200)"
      return 0
      ;;
    400)
      echo "WARNING: Slack webhook test failed (HTTP 400 - invalid payload or channel not found)."
      return 1
      ;;
    403)
      echo "WARNING: Slack webhook test failed (HTTP 403 - webhook URL is invalid or revoked)."
      return 1
      ;;
    404)
      echo "WARNING: Slack webhook test failed (HTTP 404 - webhook not found)."
      return 1
      ;;
    *)
      echo "WARNING: Slack webhook test returned unexpected HTTP ${http_code}."
      return 1
      ;;
  esac
}

if [[ -n "$SLACK_WEBHOOK" ]]; then
  if validate_slack_webhook "$SLACK_WEBHOOK"; then
    if [[ -f /etc/dhi/dhi.toml ]]; then
      if grep -q 'slack_webhook' /etc/dhi/dhi.toml; then
        sudo sed -i "s|slack_webhook[[:space:]]*=.*|slack_webhook = \"${SLACK_WEBHOOK}\"|" /etc/dhi/dhi.toml
      else
        printf '\n[alerting]\nslack_webhook = "%s"\n' "${SLACK_WEBHOOK}" | sudo tee -a /etc/dhi/dhi.toml >/dev/null
      fi
      echo "Slack webhook configured in /etc/dhi/dhi.toml"
    else
      echo "WARNING: /etc/dhi/dhi.toml not found; could not write Slack webhook."
      echo "         Set it manually: [alerting] slack_webhook = \"${SLACK_WEBHOOK}\""
    fi
  else
    echo "WARNING: Slack webhook was not saved due to validation failure."
    echo "         Fix the URL and update /etc/dhi/dhi.toml manually:"
    echo "           [alerting]"
    echo "           slack_webhook = \"<your-valid-webhook-url>\""
  fi
fi

# Company name for report branding (optional)
if [[ -t 0 ]]; then
  echo
  echo "Report branding (optional)"
  echo "  Dhi generates daily security reports with company branding."
  printf "  Enter your company name, or press Enter to use default (Seconize): "
  read -r _input_company
  if [[ -n "$_input_company" ]]; then
    if [[ -f /etc/dhi/dhi.toml ]]; then
      if grep -q 'company_name' /etc/dhi/dhi.toml; then
        sudo sed -i "s|company_name[[:space:]]*=.*|company_name = \"${_input_company}\"|" /etc/dhi/dhi.toml
      else
        if grep -q '^\[reporting\]' /etc/dhi/dhi.toml; then
          sudo sed -i "/^\[reporting\]/a company_name = \"${_input_company}\"" /etc/dhi/dhi.toml
        else
          printf '\n[reporting]\ncompany_name = "%s"\n' "${_input_company}" | sudo tee -a /etc/dhi/dhi.toml >/dev/null
        fi
      fi
      echo "Company name configured in /etc/dhi/dhi.toml"
    else
      echo "WARNING: /etc/dhi/dhi.toml not found; could not write company name."
      echo "         Set it manually: [reporting] company_name = \"${_input_company}\""
    fi
  else
    echo "  Skipped (using default). You can update it later in /etc/dhi/dhi.toml under [reporting] company_name."
  fi
  unset _input_company
fi

if install_logrotate_pkg; then
  if install_logrotate_policy; then
    if logrotate -d /etc/logrotate.d/dhi >/dev/null 2>&1; then
      echo "logrotate policy validation: ok"
    else
      echo "WARNING: logrotate policy validation failed."
    fi
    check_rotation_scheduler || true
  fi
else
  echo "WARNING: logrotate is not installed; log files may grow unbounded if you configure file logging."
fi

if ! command -v systemctl >/dev/null 2>&1; then
  print_non_systemd_guidance
elif install_systemd_service; then
  echo "Installing systemd service"
  sudo systemctl daemon-reload
  sudo systemctl enable dhi
  echo "Dhi service installed and enabled."
  echo "Start now with: sudo systemctl start dhi"

  if install_health_check_script && install_health_systemd_units; then
    sudo systemctl daemon-reload
    if [[ "$ENABLE_HEALTH_TIMER" == "1" ]]; then
      sudo systemctl enable --now dhi-health-check.timer
      echo "Health-check timer installed and enabled (1-minute interval)."
    else
      echo "Health-check timer installed but not enabled (DHI_ENABLE_HEALTH_TIMER=${ENABLE_HEALTH_TIMER})."
      echo "Enable it later with: sudo systemctl enable --now dhi-health-check.timer"
    fi
  else
    echo "WARNING: Health-check automation artifacts were not fully installed."
  fi
else
  echo "WARNING: Could not install systemd service."
  echo "         You can still run Dhi manually: sudo dhi --config /etc/dhi/dhi.toml --level alert"
fi

echo "Done. Installed:"
echo "  - /usr/local/bin/dhi"
echo "  - /usr/share/dhi/dhi_ssl.bpf.o"
echo "  - /etc/dhi/dhi.toml (and dhi.toml.example)"
echo "  - /etc/dhi/dhi.patterns.toml (and dhi.patterns.toml.example)"
echo "  - ${LOG_ROOT}"
echo "  - ${LOG_ROOT}/reports"
if command -v systemctl >/dev/null 2>&1; then
  echo "  - systemd service (dhi.service)"
  echo "  - health-check script (/usr/local/bin/dhi-health-check)"
  echo "  - health-check timer (dhi-health-check.timer)"
fi
echo
echo "Default runtime behavior: logs -> stdout/journald, reports -> ${LOG_ROOT}/reports"
echo "To use production file paths, set in config:"
echo "  [logging] file = \"${LOG_ROOT}/dhi.log\""
echo "  [reporting] output_dir = \"${LOG_ROOT}/reports\""
echo
echo "To start Dhi as a service:"
echo "  sudo systemctl start dhi"
echo "  sudo systemctl status dhi"
echo "  sudo journalctl -u dhi -f"
echo "To inspect health automation:"
echo "  sudo systemctl status dhi-health-check.timer"
echo "  sudo journalctl -u dhi-health-check.service -f"
echo "To run verification later without reinstalling:"
echo "  sudo ./scripts/install-linux-release.sh --verify-only"
if [[ -z "$SLACK_WEBHOOK" ]]; then
  echo
  echo "Slack alerting is not configured yet."
  echo "  To enable it, set slack_webhook in /etc/dhi/dhi.toml:"
  echo "    [alerting]"
  echo "    slack_webhook = \"https://hooks.slack.com/services/YOUR/WEBHOOK/URL\""
  echo "  Or re-run the installer with: --slack-webhook <url>"
fi

run_post_install_verification
