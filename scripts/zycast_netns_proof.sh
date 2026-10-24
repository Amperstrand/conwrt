#!/bin/bash
# zycast_netns_proof.sh — hardware-safe functional proof of a conwrt-zycast binary.
#
# Runs the sender under qemu-mipsel inside an isolated network namespace
# (loopback only — zero packets leave this host), captures the multicast
# frames, and verifies them against the wire format with
# scripts/zycast_wire_check.py. Proves: correct zycast framing, payload
# fidelity, chunk ordering across loops, and bounded sender exit.
#
# Usage: scripts/zycast_netns_proof.sh <binary> [loops]
#        scripts/zycast_netns_proof.sh --host [loops]   (host conwrt CLI)
# A MIPS binary runs under qemu-mipsel-static (needs the SDK musl
# sysroot at data/sdk-lane/toolchain-*/mipsel-openwrt-linux-musl);
# anything else — including --host, which builds and runs the native
# `conwrt zycast` — executes directly. Requires sudo -n (unshare) and
# tcpdump either way.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO="$(command -v cargo || echo "/home/ubuntu/.cargo/bin/cargo")"
if [ "${1:-}" = "--host" ]; then
  "$CARGO" build -q --manifest-path "$REPO_ROOT/Cargo.toml" -p conwrt-cli
  BIN="$REPO_ROOT/target/debug/conwrt"
  LOOPS="${2:-2}"
else
  BIN="${1:?usage: zycast_netns_proof.sh <binary>|--host [loops]}"
  LOOPS="${2:-2}"
fi
SYSROOT="$({ ls -d "$REPO_ROOT"/data/sdk-lane/toolchain-*/mipsel-openwrt-linux-musl 2>/dev/null || true; } | head -1)"
IS_MIPS="$(file -b "$BIN" 2>/dev/null | grep -ci mips || true)"
if [ "$IS_MIPS" = 1 ]; then
  [ -n "$SYSROOT" ] || { echo "no SDK musl sysroot under data/sdk-lane/ (see docs/toolchain-lane-2026-10-22.md §6)" >&2; exit 1; }
  command -v qemu-mipsel-static >/dev/null || { echo "qemu-mipsel-static not installed" >&2; exit 1; }
  RUN_CMD='timeout 25 qemu-mipsel-static -L '"$SYSROOT"' '"$BIN"' send -i lo --loops '"$LOOPS"' --delay-ms 2 --loop-gap-ms 10'
else
  # --confirm-specimen: the netns loopback IS the isolation (no other
  # ZyXEL unit can hear this multicast) — the AGENTS specimen rule is
  # satisfied by construction here.
  # slower per-packet cadence than real use: gives the capture a stable
  # window (the qemu/mipsel sender was slow enough not to need this)
  RUN_CMD='timeout 25 '"$BIN"' zycast -i lo --loops '"$LOOPS"' --delay-ms 200 --confirm-specimen'
fi

IMG="$(mktemp /tmp/zycast-proof-img.XXXXXX)"
# NOT mktemp: a pre-created mode-600 file is unwritable by tcpdump,
# which drops privileges to its own user after opening the capture.
PCAP="/tmp/zycast-proof.$$.$RANDOM.pcap"
trap 'rm -f "$IMG"; sudo -n rm -f "$PCAP" 2>/dev/null || true' EXIT
head -c 4096 /dev/urandom > "$IMG"

sudo -n unshare -n bash -c '
  set -e
  ip link set lo up
  ip route add 224.0.0.0/4 dev lo 2>/dev/null || true
  cd "'"$REPO_ROOT"'"
  timeout 20 tcpdump -i lo -c '"$((4 * LOOPS))"' -w "'"$PCAP"'" "udp port 5631" 2>/dev/null &
  TPID=$!
  sleep 1.5
  '"$RUN_CMD"' "'"$IMG"'"
  wait $TPID 2>/dev/null || true
'
python3 "$REPO_ROOT/scripts/zycast_wire_check.py" "$PCAP" "$IMG" --loops "$LOOPS"
