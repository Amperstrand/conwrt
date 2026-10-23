#!/bin/bash
# zycast_netns_proof.sh — hardware-safe functional proof of a conwrt-zycast binary.
#
# Runs the sender under qemu-mipsel inside an isolated network namespace
# (loopback only — zero packets leave this host), captures the multicast
# frames, and verifies them against the wire format with
# scripts/zycast_wire_check.py. Proves: correct zycast framing, payload
# fidelity, chunk ordering across loops, and bounded sender exit.
#
# Usage: scripts/zycast_netns_proof.sh <mipsel-binary> [loops]
# Requires: sudo -n (unshare), qemu-mipsel-static, tcpdump, and the SDK
# musl sysroot at data/sdk-lane/toolchain-*/mipsel-openwrt-linux-musl.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:?usage: zycast_netns_proof.sh <mipsel-binary> [loops]}"
LOOPS="${2:-2}"
SYSROOT="$(ls -d "$REPO_ROOT"/data/sdk-lane/toolchain-*/mipsel-openwrt-linux-musl 2>/dev/null | head -1)"
[ -n "$SYSROOT" ] || { echo "no SDK musl sysroot under data/sdk-lane/ (see docs/toolchain-lane-2026-10-22.md §6)" >&2; exit 1; }
command -v qemu-mipsel-static >/dev/null || { echo "qemu-mipsel-static not installed" >&2; exit 1; }

IMG="$(mktemp /tmp/zycast-proof-img.XXXXXX)"
PCAP="$REPO_ROOT/data/sdk-lane/netns-proof.pcap"
trap 'rm -f "$IMG"' EXIT
head -c 4096 /dev/urandom > "$IMG"

sudo -n unshare -n bash -c '
  set -e
  ip link set lo up
  ip route add 224.0.0.0/4 dev lo 2>/dev/null || true
  cd "'"$REPO_ROOT"'"
  timeout 20 tcpdump -i lo -c '"$((4 * LOOPS))"' -w "'"$PCAP"'" "udp port 5631" 2>/dev/null &
  TPID=$!
  sleep 0.7
  timeout 25 qemu-mipsel-static -L "'"$SYSROOT"'" "'"$BIN"'" \
    send -i lo --loops '"$LOOPS"' --delay-ms 2 --loop-gap-ms 10 "'"$IMG"'"
  wait $TPID 2>/dev/null || true
'
python3 "$REPO_ROOT/scripts/zycast_wire_check.py" "$PCAP" "$IMG" --loops "$LOOPS"
