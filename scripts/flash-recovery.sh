#!/usr/bin/env bash
#
# Generic recovery/reflash helper for conwrt — works for any model in
# models/, not just one device.
#
# For a model whose recovery method is HTTP-based (uboot-http / recovery-http,
# e.g. GL.iNet, D-Link, COMFAST), it briefly takes over the recovery subnet on
# the wired NIC to verify the bootloader recovery server is ARMED, then hands
# off to `conwrt flash`. Arming is detected from the ARP layer only: the
# one-request recovery-server class (D-Link COVR x1860 et al.) serves exactly
# ONE HTTP request, so any GET probe burns the arming window and costs a power
# cycle (docs/DLINK-RECOVERY-FLASH-RUNBOOK.md §2 rule 1). FORCE_HTTP_PROBE=1
# restores the legacy GET probe for multi-request recovery server classes
# (GL.iNet). Models without an HTTP recovery address (serial/TFTP/zycast)
# skip the probe and go straight to conwrt.
#
# It caches sudo and keeps it alive (post-flash provisioning shells out to
# `sudo -n`), and always removes the temporary recovery IP/route afterwards.
#
# Usage:
#   scripts/flash-recovery.sh [MODEL] [INTERFACE]
#   MODEL=glinet-mt3000 IFACE=enp0s31f6 scripts/flash-recovery.sh
#   FORCE_UBOOT=1 scripts/flash-recovery.sh glinet-mt3000   # force U-Boot path
#   DRY_RUN=1 scripts/flash-recovery.sh glinet-mt3000       # probe only, never GETs
#   FORCE_HTTP_PROBE=1 scripts/flash-recovery.sh glinet-mt3000  # legacy GET probe
#                                                             # (multi-request
#                                                             # recovery servers)
#
set -euo pipefail

MODEL="${1:-${MODEL:-}}"
IFACE="${2:-${IFACE:-}}"
FORCE_UBOOT="${FORCE_UBOOT:-0}"
FORCE_HTTP_PROBE="${FORCE_HTTP_PROBE:-0}"
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
# Recovery arming detection — ARP-only by default
# ---------------------------------------------------------------------------
# One-request recovery servers (D-Link COVR x1860 class) serve exactly ONE
# HTTP request; a GET probe burns the arming window and costs a power cycle
# (docs/DLINK-RECOVERY-FLASH-RUNBOOK.md §2 rule 1). Arming is therefore
# detected at the ARP layer: solicit the recovery IP with an ICMP ping (the
# recovery stack answers ARP, never ICMP) and read the neighbor entry —
# REACHABLE/STALE/DELAY/PROBE with a MAC present means the U-Boot stack is
# live and would serve its one request. FORCE_HTTP_PROBE=1 restores the
# legacy GET probe for multi-request server classes (GL.iNet); DRY_RUN=1
# never issues an HTTP request in either mode.
if [[ -n "$RECOVERY_IP" && -n "$CLIENT_IP" ]]; then
  LINK_STATE="$(cat "/sys/class/net/$IFACE/operstate" 2>/dev/null || echo unknown)"
  info "Wired link '$IFACE' state: $LINK_STATE"
  [[ "$LINK_STATE" == "up" || "$LINK_STATE" == "unknown" ]] \
    || warn "No carrier on $IFACE — check the ethernet cable."

  sudo ip link set "$IFACE" up
  sudo ip addr add "$CLIENT_IP/24" dev "$IFACE" 2>/dev/null || true
  sudo ip route replace "$RECOVERY_IP/32" dev "$IFACE"

  ARMED=0
  ARM_EVIDENCE=""
  if [[ "$FORCE_HTTP_PROBE" == "1" && "${DRY_RUN:-0}" != "1" ]]; then
    info "FORCE_HTTP_PROBE=1 — GETting recovery web server at http://$RECOVERY_IP/ …"
    PAGE="$(curl -s --max-time 5 "http://$RECOVERY_IP/" || true)"
    if [[ -n "$PAGE" ]]; then
      ARMED=1
      ARM_EVIDENCE="HTTP response"
    fi
  else
    command -v ping >/dev/null \
      || die "ping not found (needed to solicit ARP for the recovery probe)."
    # Drop any stale neighbor entry first, so the verdict below can only come
    # from ARP resolved during THIS probe — not a leftover from an earlier
    # session against stock firmware on the same address.
    sudo ip neigh del "$RECOVERY_IP" dev "$IFACE" 2>/dev/null || true
    info "Waiting for ARP from $RECOVERY_IP (armed = it answers ARP)…"
    for _ in 1 2 3 4 5; do
      ping -c 1 -W 1 "$RECOVERY_IP" >/dev/null 2>&1 || true
      NEIGH="$(ip neigh show "$RECOVERY_IP" dev "$IFACE" 2>/dev/null || true)"
      # MAC present + live-ish state (not INCOMPLETE/FAILED/absent) = armed.
      if [[ "$NEIGH" =~ lladdr[[:space:]]+([0-9a-fA-F:]{17})[[:space:]]+(REACHABLE|STALE|DELAY|PROBE) ]]; then
        ARMED=1
        ARM_EVIDENCE="ARP ${BASH_REMATCH[2]} ${BASH_REMATCH[1]}"
        break
      fi
      sleep 1
    done
  fi
  # Remove the temporary config so conwrt's stale-IP pre-flight stays clean;
  # conwrt re-adds it itself right before detecting boot state.
  net_down

  if [[ "$ARMED" == "1" ]]; then
    info "Recovery server armed ($ARM_EVIDENCE)."
  else
    warn "No ARP response from $RECOVERY_IP (no HTTP response in FORCE_HTTP_PROBE mode)."
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
