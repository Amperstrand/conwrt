#!/usr/bin/env bash
#
# Generic recovery/reflash helper for conwrt — works for any model in
# models/, not just one device.
#
# For a model whose recovery method is HTTP-based (uboot-http / recovery-http,
# e.g. GL.iNet, D-Link, COMFAST), it briefly takes over the recovery subnet on
# the wired NIC to VERIFY the bootloader web server is up, then hands off to
# `conwrt flash`. Models without an HTTP recovery address (serial/TFTP/zycast)
# skip the probe and go straight to conwrt.
#
# It caches sudo and keeps it alive (post-flash provisioning shells out to
# `sudo -n`), and always removes the temporary recovery IP/route afterwards.
#
# Usage:
#   scripts/flash-recovery.sh [MODEL] [INTERFACE]
#   MODEL=glinet-mt3000 IFACE=enp0s31f6 scripts/flash-recovery.sh
#   FORCE_UBOOT=1 scripts/flash-recovery.sh glinet-mt3000   # force U-Boot path
#   DRY_RUN=1 scripts/flash-recovery.sh glinet-mt3000       # probe only
#
set -euo pipefail

MODEL="${1:-${MODEL:-}}"
IFACE="${2:-${IFACE:-}}"
FORCE_UBOOT="${FORCE_UBOOT:-0}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

info() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!!! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31mERR: %s\033[0m\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -ne 0 ]] || die "Run as your normal user, not root (the script sudo's as needed)."
command -v ip >/dev/null || die "iproute2 ('ip') not found."
[[ -f "$REPO_DIR/scripts/conwrt.py" && -d "$REPO_DIR/models" ]] \
  || die "This script must live in the conwrt checkout (scripts/conwrt.py not found)."

if [[ -d "$REPO_DIR/.venv" ]]; then
  # shellcheck disable=SC1091
  source "$REPO_DIR/.venv/bin/activate"
  PY=python
else
  PY=python3
fi

cd "$REPO_DIR"

# --- model / interface lookup (via the same code conwrt uses) --------------
model_recovery() {  # -> "RECOVERY_IP CLIENT_IP" (either may be empty)
  "$PY" -c '
import sys
sys.path.insert(0, "scripts")
try:
    from flash.device_profile import build_profile_from_model as b
    p = b(sys.argv[1])
    print(getattr(p, "recovery_ip", "") or "", getattr(p, "client_ip", "") or "")
except Exception:
    print("", "")
' "$1"
}

detect_iface() {
  "$PY" -c '
import sys
sys.path.insert(0, "scripts")
try:
    from conwrt.device_inventory import auto_detect_interface as a
    print(a() or "")
except Exception:
    print("")
'
}

[[ -n "$IFACE" ]] || IFACE="$(detect_iface)"
[[ -n "$IFACE" ]] || die "No wired interface found; pass one: scripts/flash-recovery.sh MODEL enp0s31f6"
[[ -e "/sys/class/net/$IFACE" ]] || die "Interface '$IFACE' not found."

RECOVERY_IP=""
CLIENT_IP=""
if [[ -n "$MODEL" ]]; then
  read -r RECOVERY_IP CLIENT_IP < <(model_recovery "$MODEL")
fi

# ---------------------------------------------------------------------------
# sudo + cleanup trap
# ---------------------------------------------------------------------------
info "Requesting sudo (needed to configure $IFACE for recovery)…"
sudo -v || die "sudo failed or was cancelled."

net_down() {
  [[ -n "$RECOVERY_IP" && -n "$CLIENT_IP" ]] || return 0
  sudo ip route del "$RECOVERY_IP/32" dev "$IFACE" 2>/dev/null || true
  sudo ip addr del "$CLIENT_IP/24" dev "$IFACE" 2>/dev/null || true
}

SUDO_KEEPALIVE=""
cleanup() {
  local rc=$?
  [[ -n "$SUDO_KEEPALIVE" ]] && kill "$SUDO_KEEPALIVE" 2>/dev/null || true
  net_down
  trap - EXIT INT TERM
  return $rc
}
trap cleanup EXIT INT TERM

( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
SUDO_KEEPALIVE=$!

# ---------------------------------------------------------------------------
# Optional HTTP recovery probe (only when the model exposes a recovery IP)
# ---------------------------------------------------------------------------
if [[ -n "$RECOVERY_IP" && -n "$CLIENT_IP" ]]; then
  LINK_STATE="$(cat "/sys/class/net/$IFACE/operstate" 2>/dev/null || echo unknown)"
  info "Wired link '$IFACE' state: $LINK_STATE"
  [[ "$LINK_STATE" == "up" || "$LINK_STATE" == "unknown" ]] \
    || warn "No carrier on $IFACE — check the ethernet cable."

  info "Probing recovery web server at http://$RECOVERY_IP/ …"
  sudo ip link set "$IFACE" up
  sudo ip addr add "$CLIENT_IP/24" dev "$IFACE" 2>/dev/null || true
  sudo ip route replace "$RECOVERY_IP/32" dev "$IFACE"
  PAGE="$(curl -s --max-time 5 "http://$RECOVERY_IP/" || true)"
  # Remove the temporary config so conwrt's stale-IP pre-flight stays clean;
  # conwrt re-adds it itself right before detecting boot state.
  net_down

  if [[ -n "$PAGE" ]]; then
    info "Recovery web server responded."
  else
    warn "No response from $RECOVERY_IP."
    warn "The device may not be in recovery mode. Enter it (see the model's"
    warn "reset instructions), then retry."
    read -r -p "Continue anyway and let conwrt guide the power cycle? [y/N] " ans || ans=""
    if [[ "${ans,,}" != "y" && "${ans,,}" != "yes" ]]; then
      die "Aborted — nothing was flashed."
    fi
  fi
fi

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  info "DRY_RUN=1 — probe done; not flashing."
  exit 0
fi

# ---------------------------------------------------------------------------
# Flash via conwrt (model auto-detected when MODEL is omitted)
# ---------------------------------------------------------------------------
ARGS=(flash --no-voice)
[[ -n "$MODEL" ]] && ARGS+=(--model-id "$MODEL")
[[ -n "$IFACE" ]] && ARGS+=(--interface "$IFACE")
[[ "$FORCE_UBOOT" == "1" ]] && ARGS+=(--force-uboot)

info "Running: conwrt ${ARGS[*]}"
"$PY" scripts/conwrt.py "${ARGS[@]}"

info "Flash complete."
