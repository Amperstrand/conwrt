"""LAN role election — the "listener-first" conditional network bringup.

The rogue-DHCP problem for users without VLANs: a freshly flashed unit is
stock OpenWrt (br-lan 192.168.1.1, DHCP+RA serving). Plugged into a shared
LAN it either fights the real router or is invisible in plain sight.
Baking a static lan_ip helps only when the operator knows the target
network. The election fragment closes the gap by construction:

  first boot (and ONLY first boot — uci-defaults exit-0 => deleted):
    1. probe for an upstream DHCP server (~60 s, udhcpc, no side effects)
    2. lease seen  -> LAN-citizen: network.lan.proto=dhcp, our DHCP/RA off
    3. no lease    -> classic gateway: keep the stock static default

Prior art: OpenWrt dumb-AP pattern (proto dhcp + dhcp.lan.ignore=1) is
established practice; the conditional variant was proposed on the OpenWrt
forum (t/36222, 2019) with the canonical objection that a router must
never be role-confused at runtime — answered here by scoping the election
to first boot, client-biased, never re-evaluated. Production identity
still comes from stage 2 / the fleet profile.

Design doc: conwrt-bench docs/nr7101/PROVISIONING-PORT-AND-ELECTION-PLAN.md
(2026-11-25, research-grounded). Hardware validation: campaign conwrt #841
E5.
"""
from __future__ import annotations

# BusyBox-safe: runs from /etc/uci-defaults BEFORE netifd's first bring-up
# (S10boot runs uci-defaults; network starts later), so the elected role
# applies to the first network configuration — no restart, no flap.
# -s /bin/true: accept the probe lease with zero side effects; netifd
# re-requests properly once it brings the interface up.
ELECTION_TEMPLATE = """#!/bin/sh
# conwrt LAN role election (first boot only) — do not edit, generated.
# Lease seen upstream => we are a guest on this network (DHCP client, our
# servers off). No lease => we are the network (stock static default).
IFACE='{iface}'
LOG=/tmp/conwrt-election.log
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') election: probing {iface} for an upstream DHCP server" > $LOG
ip link set "$IFACE" up 2>/dev/null || true
if udhcpc -i "$IFACE" -n -q -T {probe_period} -t {probe_tries} -f -s /bin/true >> $LOG 2>&1; then
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') election: LEASE seen -> LAN-citizen mode" >> $LOG
  uci -q batch <<EOI
set network.lan.proto='dhcp'
delete network.lan.ipaddr
delete network.lan.netmask
set dhcp.lan.ignore='1'
set dhcp.lan.ra='disabled'
set dhcp.lan.dhcpv6='disabled'
EOI
  uci commit network
  uci commit dhcp
else
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') election: NO lease -> gateway mode (stock default)" >> $LOG
fi
exit 0
"""

# Default probe: 12 tries x 5 s = ~60 s (the plan doc's spec; long enough
# for a slow-booting home router to start serving, short enough not to
# feel dead on an isolated bench port).
DEFAULT_PROBE_TRIES = 12
DEFAULT_PROBE_PERIOD = 5


def election_script(iface: str = "eth0",
                    probe_tries: int = DEFAULT_PROBE_TRIES,
                    probe_period: int = DEFAULT_PROBE_PERIOD) -> bytes:
    """Render the uci-defaults election script for a model's LAN port."""
    if not iface or any(c.isspace() or "'" in iface or "$" in iface for c in iface):
        raise ValueError(f"iface must be a plain interface name, got {iface!r}")
    if probe_tries < 1 or probe_period < 1:
        raise ValueError("probe_tries and probe_period must be >= 1")
    return ELECTION_TEMPLATE.format(
        iface=iface, probe_tries=probe_tries, probe_period=probe_period,
    ).encode("utf-8")
