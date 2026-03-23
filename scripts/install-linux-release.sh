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

REPO="seconize-co/dhi"
LOG_ROOT="${DHI_LOG_ROOT:-/var/log/dhi}"
VERIFY_ONLY=0
POSITIONAL=()

for arg in "$@"; do
  case "$arg" in
    --verify-only)
      VERIFY_ONLY=1
      ;;
    -h|--help)
      echo "Install Dhi from GitHub release artifacts (Linux only)."
      echo
      echo "Usage:"
      echo "  $0 <version-tag>"
      echo "  DHI_VERSION=<version-tag> $0"
      echo "  $0 --verify-only"
      echo
      echo "Examples:"
      echo "  $0 v1.2.3"
      echo "  DHI_VERSION=v1.2.3 $0"
      echo "  $0 --verify-only"
      exit 0
      ;;
    *)
      POSITIONAL+=("$arg")
      ;;
  esac
done

if [[ "${#POSITIONAL[@]}" -gt 1 ]]; then
  echo "Too many positional arguments."
  echo "Usage: $0 <version-tag> | $0 --verify-only"
  exit 1
fi

VERSION="${POSITIONAL[0]:-${DHI_VERSION:-}}"

if [[ "$VERIFY_ONLY" -eq 0 && -z "$VERSION" ]]; then
  echo "Usage: $0 <version-tag>  (example: $0 v1.2.3)"
  echo "Or set DHI_VERSION=v1.2.3"
  echo "Or run verification only: $0 --verify-only"
  exit 1
fi

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

URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
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
  local remote_policy="https://raw.githubusercontent.com/${REPO}/${VERSION}/ops/logrotate/dhi"
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
  local remote_service="https://raw.githubusercontent.com/${REPO}/${VERSION}/ops/systemd/dhi.service"
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

install_config_file() {
  if [[ ! -f "$TMPDIR/etc/dhi/dhi.toml.example" ]]; then
    echo "WARNING: Config template not found in release archive."
    return 1
  fi

  sudo install -d /etc/dhi
  
  # Install template
  sudo install -m 644 "$TMPDIR/etc/dhi/dhi.toml.example" /etc/dhi/dhi.toml.example
  
  # Create config only if it doesn't exist (preserve on upgrades)
  if [[ ! -f /etc/dhi/dhi.toml ]]; then
    sudo install -m 644 "$TMPDIR/etc/dhi/dhi.toml.example" /etc/dhi/dhi.toml
    return 0
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

echo "Creating production log/report directories at ${LOG_ROOT}"
sudo install -d "$LOG_ROOT" "$LOG_ROOT/reports"

if install_config_file; then
  echo "Config files installed to /etc/dhi/"
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
else
  echo "WARNING: Could not install systemd service."
  echo "         You can still run Dhi manually: sudo dhi --config /etc/dhi/dhi.toml --level alert"
fi

echo "Done. Installed:"
echo "  - /usr/local/bin/dhi"
echo "  - /usr/share/dhi/dhi_ssl.bpf.o"
echo "  - /etc/dhi/dhi.toml (and dhi.toml.example)"
echo "  - ${LOG_ROOT}"
echo "  - ${LOG_ROOT}/reports"
if command -v systemctl >/dev/null 2>&1; then
  echo "  - systemd service (dhi.service)"
fi
echo
echo "Default runtime behavior: logs -> stdout/journald, reports -> ./dhi-reports"
echo "To use production file paths, set in config:"
echo "  [logging] file = \"${LOG_ROOT}/dhi.log\""
echo "  [reporting] output_dir = \"${LOG_ROOT}/reports\""
echo
echo "To start Dhi as a service:"
echo "  sudo systemctl start dhi"
echo "  sudo systemctl status dhi"
echo "  sudo journalctl -u dhi -f"
echo "To run verification later without reinstalling:"
echo "  sudo ./scripts/install-linux-release.sh --verify-only"

run_post_install_verification
