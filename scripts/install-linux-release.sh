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
VERSION="${1:-${DHI_VERSION:-}}"
LOG_ROOT="${DHI_LOG_ROOT:-/var/log/dhi}"

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version-tag>  (example: $0 v1.2.3)"
  echo "Or set DHI_VERSION=v1.2.3"
  exit 1
fi

if [[ "${OSTYPE:-}" != linux* ]]; then
  echo "This installer supports Linux only."
  exit 1
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
  echo "WARNING: systemd not detected; Dhi service will not be registered."
  echo "         You can still run Dhi manually: sudo dhi --level alert"
elif install_systemd_service; then
  echo "Installing systemd service"
  sudo systemctl daemon-reload
  sudo systemctl enable dhi
  echo "Dhi service installed and enabled."
  echo "Start now with: sudo systemctl start dhi"
else
  echo "WARNING: Could not install systemd service."
  echo "         You can still run Dhi manually: sudo dhi --level alert"
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
