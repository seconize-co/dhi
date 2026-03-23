#!/usr/bin/env bash
set -euo pipefail

# Uninstall Dhi from Linux hosts.
# Removes binaries, configs, eBPF artifacts, systemd units, and (by default) logs.
#
# Usage:
#   ./scripts/uninstall-linux.sh
#   ./scripts/uninstall-linux.sh --dry-run
#   ./scripts/uninstall-linux.sh --keep-logs
#   ./scripts/uninstall-linux.sh --purge-all

DRY_RUN=0
KEEP_LOGS=0
PURGE_ALL=0
CONFIG_PATH="/etc/dhi/dhi.toml"
EXTRA_PATHS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --keep-logs)
      KEEP_LOGS=1
      shift
      ;;
    --purge-all)
      PURGE_ALL=1
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Uninstall Dhi from Linux hosts.

Usage:
  ./scripts/uninstall-linux.sh [--dry-run] [--keep-logs] [--purge-all] [--config <path>] [--extra-path <path> ...]

Options:
  --dry-run     Print actions only (no changes made)
  --keep-logs   Keep /var/log/dhi
  --purge-all   Also remove optional installer extras (logrotate policy, lock file)
  --config      Path to Dhi config file (default: /etc/dhi/dhi.toml)
  --extra-path  Additional absolute file/dir path to remove (repeatable)
EOF
      exit 0
      ;;
    --config)
      if [[ $# -lt 2 ]]; then
        echo "--config requires a path argument" >&2
        exit 1
      fi
      CONFIG_PATH="$2"
      shift 2
      ;;
    --extra-path)
      if [[ $# -lt 2 ]]; then
        echo "--extra-path requires a path argument" >&2
        exit 1
      fi
      EXTRA_PATHS+=("$2")
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "${OSTYPE:-}" != linux* ]]; then
  echo "This uninstall script supports Linux only."
  exit 1
fi

if [[ "$KEEP_LOGS" -eq 1 && "$PURGE_ALL" -eq 1 ]]; then
  echo "Warning: --purge-all includes log cleanup unless --keep-logs is set."
fi

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $*"
  else
    eval "$*"
  fi
}

sudo_cmd() {
  if [[ "$(id -u)" -eq 0 ]]; then
    run "$*"
  else
    run "sudo $*"
  fi
}

echo "== Dhi Uninstall =="
echo "dry-run:   $DRY_RUN"
echo "keep-logs: $KEEP_LOGS"
echo "purge-all: $PURGE_ALL"
echo "config:    $CONFIG_PATH"
if [[ "${#EXTRA_PATHS[@]}" -gt 0 ]]; then
  echo "extra-paths:"
  for p in "${EXTRA_PATHS[@]}"; do
    echo "  - $p"
  done
fi
echo

is_cleanup_path_safe() {
  local p="$1"
  [[ -n "$p" ]] || return 1
  [[ "$p" = /* ]] || return 1
  case "$p" in
    /|/etc|/usr|/var|/home|/root|/tmp)
      return 1
      ;;
  esac
  return 0
}

if command -v systemctl >/dev/null 2>&1; then
  echo "Stopping and disabling Dhi services..."
  sudo_cmd "systemctl stop dhi 2>/dev/null || true"
  sudo_cmd "systemctl disable dhi 2>/dev/null || true"
  sudo_cmd "systemctl stop dhi-health-check.timer 2>/dev/null || true"
  sudo_cmd "systemctl disable dhi-health-check.timer 2>/dev/null || true"
  sudo_cmd "systemctl stop dhi-health-check.service 2>/dev/null || true"
fi

echo "Stopping remaining Dhi processes (if any)..."
mapfile -t DHI_PIDS < <(ps -eo pid,comm | awk '$2=="dhi" {print $1}')
for pid in "${DHI_PIDS[@]:-}"; do
  if [[ -n "$pid" ]]; then
    sudo_cmd "kill $pid 2>/dev/null || true"
  fi
done

declare -a CUSTOM_CLEANUP_PATHS=()
collect_custom_paths_from_config() {
  local cfg="$1"
  if [[ ! -f "$cfg" ]]; then
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "WARNING: python3 not found; skipping custom path parsing from $cfg"
    return 0
  fi

  mapfile -t CUSTOM_CLEANUP_PATHS < <(python3 - "$cfg" <<'PY'
import os
import sys

cfg_path = sys.argv[1]
try:
    import tomllib  # py3.11+
except Exception:
    try:
        import tomli as tomllib  # type: ignore
    except Exception:
        print("WARN_NO_TOML_PARSER")
        raise SystemExit(0)

with open(cfg_path, "rb") as f:
    data = tomllib.load(f)

paths = []
logging_file = data.get("logging", {}).get("file")
if isinstance(logging_file, str) and logging_file.strip():
    paths.append(logging_file.strip())

reporting_dir = data.get("reporting", {}).get("output_dir")
if isinstance(reporting_dir, str) and reporting_dir.strip():
    paths.append(reporting_dir.strip())

alert_log = data.get("alerting", {}).get("alert_log_path")
if isinstance(alert_log, str) and alert_log.strip():
    paths.append(alert_log.strip())

for p in paths:
    if not os.path.isabs(p):
        continue
    normalized = os.path.normpath(p)
    if normalized in ("/", "/etc", "/usr", "/var", "/home", "/root", "/tmp"):
        continue
    print(normalized)
PY
  )

  if [[ "${#CUSTOM_CLEANUP_PATHS[@]}" -gt 0 && "${CUSTOM_CLEANUP_PATHS[0]}" == "WARN_NO_TOML_PARSER" ]]; then
    CUSTOM_CLEANUP_PATHS=()
    echo "WARNING: no TOML parser available in python3; skipping custom path parsing from $cfg"
  fi
}

collect_custom_paths_from_config "$CONFIG_PATH"
if [[ "${#CUSTOM_CLEANUP_PATHS[@]}" -gt 0 ]]; then
  echo "Detected custom paths from config:"
  for p in "${CUSTOM_CLEANUP_PATHS[@]}"; do
    echo "  - $p"
  done
fi

declare -a EXTRA_CLEANUP_PATHS=()
if [[ "${#EXTRA_PATHS[@]}" -gt 0 ]]; then
  for p in "${EXTRA_PATHS[@]}"; do
    if is_cleanup_path_safe "$p"; then
      EXTRA_CLEANUP_PATHS+=("$p")
    else
      echo "WARNING: ignoring unsafe --extra-path value: $p"
    fi
  done
fi

echo "Removing binaries and install artifacts..."
sudo_cmd "rm -f /usr/local/bin/dhi /usr/local/bin/dhi-health-check"
sudo_cmd "rm -rf /usr/share/dhi"

if [[ "$KEEP_LOGS" -eq 0 ]]; then
  sudo_cmd "rm -rf /var/log/dhi"
  for path in "${CUSTOM_CLEANUP_PATHS[@]:-}"; do
    if [[ -z "$path" ]]; then
      continue
    fi
    if ! is_cleanup_path_safe "$path"; then
      echo "WARNING: skipping unsafe config-derived cleanup path: $path"
      continue
    fi
    # If path points to a file, remove file; if directory, remove directory.
    sudo_cmd "rm -rf \"$path\""
  done
else
  echo "Keeping logs: /var/log/dhi and any custom log/report paths from config"
fi

for path in "${EXTRA_CLEANUP_PATHS[@]:-}"; do
  if [[ -z "$path" ]]; then
    continue
  fi
  sudo_cmd "rm -rf \"$path\""
done

echo "Removing config directory..."
sudo_cmd "rm -rf /etc/dhi"

echo "Removing managed systemd unit files..."
sudo_cmd "rm -f /etc/systemd/system/dhi.service"
sudo_cmd "rm -f /etc/systemd/system/dhi-health-check.service"
sudo_cmd "rm -f /etc/systemd/system/dhi-health-check.timer"

if [[ "$PURGE_ALL" -eq 1 ]]; then
  echo "Purging optional installer extras..."
  sudo_cmd "rm -f /etc/logrotate.d/dhi"
  sudo_cmd "rm -f /tmp/dhi.instance.lock"
fi

if command -v systemctl >/dev/null 2>&1; then
  echo "Reloading systemd..."
  sudo_cmd "systemctl daemon-reload || true"
  sudo_cmd "systemctl reset-failed || true"
fi

echo
echo "== Verification =="
if [[ "$DRY_RUN" -eq 0 ]]; then
  command -v dhi >/dev/null 2>&1 && echo "WARN: dhi still in PATH" || echo "OK: dhi binary removed"
  systemctl is-enabled dhi >/dev/null 2>&1 && echo "WARN: dhi service still enabled" || echo "OK: dhi service disabled/not found"
  if ps -eo pid,comm | awk '$2=="dhi" {exit 0} END {exit 1}'; then
    echo "WARN: dhi process still present"
  else
    echo "OK: no running dhi process"
  fi
else
  echo "Dry-run completed. No changes made."
fi

echo "Uninstall flow complete."
