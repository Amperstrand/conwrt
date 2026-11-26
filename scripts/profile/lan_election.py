"""LAN role election — the "listener-first" conditional network bringup.

v2 (2026-11-26, campaign #841 E5B): the probe runs from an ifup HOTPLUG
hook, NOT from uci-defaults. Hardware findings that forced the redesign
(NR7101, mt7621 DSA):

- uci-defaults run at S10 BEFORE netifd: br-lan does not exist yet, the
  DSA user port is standalone, and the physical link may still be
  negotiating.
- udhcpc uses AF_PACKET raw sockets. Raw xmit on the DSA *user port*
  ("lan") does not reach the wire (observed twice on hardware); raw xmit
  on the conduit ("eth0") is untagged, which the mt7530 CPU port cannot
  dispatch (no DSA tag = no egress port). Only the BRIDGE path works —
  the same path the unit's own ARP/ICMP uses.
- Therefore: probe on br-lan, exactly when netifd first brings it up —
  the ifup hotplug hook. First-boot-only via a marker file in /overlay.

Behavior:
  first ifup of 'lan' (br-lan exists, link proven):
    probe ~20 s for an upstream DHCP server (udhcpc, no side effects)
    lease  -> LAN-citizen: proto=dhcp, our DHCP/RA off, one network
              reload to apply (a single provisioning-time flap)
    no lease -> classic gateway: keep the stock static default
  any later boot: marker present -> no-op.

Prior art: OpenWrt dumb-AP pattern (proto dhcp + dhcp.lan.ignore=1);
conditional variant proposed on the forum (t/36222, 2019) with the
role-confusion objection — answered by first-boot-only + client-biased +
never re-evaluated at runtime. Design doc: conwrt-bench
docs/nr7101/PROVISIONING-PORT-AND-ELECTION-PLAN.md.
"""
from __future__ import annotations

# Phase 1 (uci-defaults, S10): install the hotplug hook. The hook itself
# is inert until netifd emits the first 'lan' ifup.
INSTALLER_TEMPLATE = """#!/bin/sh
# conwrt LAN role election installer (first boot only) — do not edit.
# v2: the probe runs from the ifup hotplug hook (br-lan must exist; see
# the campaign E5B findings — raw-socket probes on DSA ports never leave
# the box). This script only installs the hook.
HOOK=/etc/hotplug.d/iface/96-conwrt-election
mkdir -p /etc/hotplug.d/iface
cat > "$HOOK" <<'HOOKEOF'
{hook}
HOOKEOF
chmod 755 "$HOOK"
exit 0
"""

# Phase 2 (hotplug ifup hook): the actual election.
HOOK_TEMPLATE = """#!/bin/sh
# conwrt LAN role election — first ifup of 'lan' only (marker-gated).
# Lease seen upstream => we are a guest (DHCP client, our servers off).
# No lease => we are the network (stock static default stays).
[ "$INTERFACE" = "lan" ] || exit 0
[ "$ACTION" = "ifup" ] || exit 0
[ -f /etc/conwrt-election.done ] && exit 0
BRIDGE=$(ubus call network.interface.lan status 2>/dev/null | grep -o '"l3_device": *"[^"]*"' | cut -d'"' -f4)
[ -n "$BRIDGE" ] || BRIDGE=br-lan
LOG=/tmp/conwrt-election.log
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') election: probing $BRIDGE for an upstream DHCP server" > $LOG
# ~20 s probe: 3 tries x 5 s + backoff headroom, no lease side effects.
if udhcpc -i "$BRIDGE" -n -q -T {probe_period} -t {probe_tries} -f -s /bin/true >> $LOG 2>&1; then
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
  touch /etc/conwrt-election.done
  # apply the elected role: one provisioning-time network reload
  /etc/init.d/network reload >/dev/null 2>&1 || /etc/init.d/network restart >/dev/null 2>&1
else
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') election: NO lease -> gateway mode (stock default)" >> $LOG
  touch /etc/conwrt-election.done
fi
exit 0
"""

DEFAULT_PROBE_TRIES = 3
DEFAULT_PROBE_PERIOD = 5


def election_installer(probe_tries: int = DEFAULT_PROBE_TRIES,
                       probe_period: int = DEFAULT_PROBE_PERIOD) -> bytes:
    """Render the uci-defaults installer carrying the hotplug hook."""
    if probe_tries < 1 or probe_period < 1:
        raise ValueError("probe_tries and probe_period must be >= 1")
    hook = HOOK_TEMPLATE.format(
        probe_tries=probe_tries, probe_period=probe_period,
    ).replace("{hook}", "")  # the hook is embedded via the outer format below
    # embed the hook into the installer; brace-safety: the hook contains no
    # '{'/'}' beyond the uci batch heredoc which is inert shell text
    installer = INSTALLER_TEMPLATE.replace("{hook}", hook)
    return installer.encode("utf-8")


def election_hook(probe_tries: int = DEFAULT_PROBE_TRIES,
                  probe_period: int = DEFAULT_PROBE_PERIOD) -> bytes:
    """Render just the hotplug hook (for inspection/tests)."""
    if probe_tries < 1 or probe_period < 1:
        raise ValueError("probe_tries and probe_period must be >= 1")
    return HOOK_TEMPLATE.format(
        probe_tries=probe_tries, probe_period=probe_period,
    ).encode("utf-8")
