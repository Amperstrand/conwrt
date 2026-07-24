#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ROLE=""
ROUTER_IP="192.168.1.1"
FIRMWARE=""
SSH_USER="root"
SSH_PORT=""
SETUP=""
SKIP_INSTALL=false
DRY_RUN=false

usage() {
    cat <<EOF
conwrt-flash.sh — Flash a FIPS .ipk to an OpenWrt router and run setup

Usage:
  $0 --role <role> --firmware <path> [options]

Required:
  --role <name>        fips | fips-next | fips-gateway
  --firmware <path>    Path to the .ipk file

Optional:
  --router-ip <addr>   Router IP (default: 192.168.1.1)
  --user <name>        SSH user (default: root)
  --ssh-port <port>    SSH port (default: 22)
  --setup <helper>     Setup helper to run after install:
                         mesh   → fips-mesh-setup
                         ap     → fips-ap-setup
                         gateway→ fips-gateway enable+start
  --skip-install       Skip opkg install (just run setup)
  --dry-run            Print commands without executing

Examples:
  # Flash stable FIPS to a router and create a mesh backhaul
  $0 --role fips --firmware dist/fips_0.1.0_aarch64_cortex-a53.ipk --setup mesh

  # Flash the gateway role and start the gateway service
  $0 --role fips-gateway --firmware dist/fips_0.1.0_aarch64_cortex-a53.ipk --setup gateway

  # Flash next-branch build to a staging router
  $0 --role fips-next --router-ip 192.168.1.2 --firmware dist/fips_next.ipk
EOF
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)      ROLE="$2"; shift 2 ;;
        --role=*)    ROLE="${1#*=}"; shift ;;
        --firmware)  FIRMWARE="$2"; shift 2 ;;
        --firmware=*) FIRMWARE="${1#*=}"; shift ;;
        --router-ip) ROUTER_IP="$2"; shift 2 ;;
        --router-ip=*) ROUTER_IP="${1#*=}"; shift ;;
        --user)      SSH_USER="$2"; shift 2 ;;
        --user=*)    SSH_USER="${1#*=}"; shift ;;
        --ssh-port)  SSH_PORT="$2"; shift 2 ;;
        --ssh-port=*) SSH_PORT="${1#*=}"; shift ;;
        --setup)     SETUP="$2"; shift 2 ;;
        --setup=*)   SETUP="${1#*=}"; shift ;;
        --skip-install) SKIP_INSTALL=true; shift ;;
        --dry-run)   DRY_RUN=true; shift ;;
        -h|--help)   usage 0 ;;
        *) echo "Unknown argument: $1" >&2; usage 1 ;;
    esac
done

case "$ROLE" in
    fips|fips-next|fips-gateway) ;;
    "") echo "Error: --role is required (fips, fips-next, fips-gateway)" >&2; usage 1 ;;
    *)  echo "Error: unknown role '$ROLE'" >&2; usage 1 ;;
esac

if ! $SKIP_INSTALL; then
    if [ -z "$FIRMWARE" ]; then
        echo "Error: --firmware is required (or use --skip-install)" >&2
        usage 1
    fi
    if [ ! -f "$FIRMWARE" ]; then
        echo "Error: firmware file not found: $FIRMWARE" >&2
        exit 1
    fi
fi

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
if [ -n "$SSH_PORT" ]; then
    SSH_OPTS+=(-p "$SSH_PORT")
fi

run() {
    if $DRY_RUN; then
        echo "  [dry-run] $*"
    else
        "$@"
    fi
}

remote() {
    run ssh "${SSH_OPTS[@]}" "$SSH_USER@$ROUTER_IP" "$@"
}

REMOTE_IPK="/tmp/$(basename "$FIRMWARE")"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  conwrt-flash.sh                                        ║"
echo "║  Role:       $ROLE"
echo "║  Router:     $SSH_USER@$ROUTER_IP"
if ! $SKIP_INSTALL; then
echo "║  Firmware:   $FIRMWARE"
fi
if [ -n "$SETUP" ]; then
echo "║  Setup:      $SETUP"
fi
if $DRY_RUN; then
echo "║  Mode:       DRY RUN (no changes)                       ║"
fi
echo "╚══════════════════════════════════════════════════════════╝"
echo

if ! $SKIP_INSTALL; then
    echo "==> [1/3] Copying .ipk to router..."
    run scp -O "${SSH_OPTS[@]}" "$FIRMWARE" "$SSH_USER@$ROUTER_IP:$REMOTE_IPK"

    echo "==> [2/3] Installing package via opkg..."
    remote "opkg install --force-reinstall '$REMOTE_IPK' && rm -f '$REMOTE_IPK'"
else
    echo "==> [1/3] Skipping install (--skip-install)"
    echo "==> [2/3] Skipping install (--skip-install)"
fi

echo "==> [3/3] Running setup helper..."
case "$SETUP" in
    mesh)
        echo "  Launching fips-mesh-setup (interactive — specify radio when prompted)"
        remote 'fips-mesh-setup radio0' || {
            echo "  fips-mesh-setup failed or not interactive. SSH in and run manually:" >&2
            echo "    ssh $SSH_USER@$ROUTER_IP fips-mesh-setup <radio>" >&2
        }
        ;;
    ap)
        echo "  Launching fips-ap-setup (interactive — specify radio when prompted)"
        remote 'fips-ap-setup radio1' || {
            echo "  fips-ap-setup failed or not interactive. SSH in and run manually:" >&2
            echo "    ssh $SSH_USER@$ROUTER_IP fips-ap-setup <radio>" >&2
        }
        ;;
    gateway)
        echo "  Enabling and starting fips-gateway service"
        remote '/etc/init.d/fips-gateway enable && /etc/init.d/fips-gateway start'
        ;;
    "")
        echo "  No setup helper requested (--setup not specified)."
        echo "  Available: mesh, ap, gateway"
        ;;
    *)
        echo "Error: unknown setup '$SETUP' (valid: mesh, ap, gateway)" >&2
        exit 1
        ;;
esac

echo
echo "==> Done. Verify on the router:"
echo "    ssh $SSH_USER@$ROUTER_IP fipsctl show status"
