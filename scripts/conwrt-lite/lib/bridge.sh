#!/bin/sh
# conwrt-lite bridge library — DSA bridge port isolation for safe TFTP flashing
#
# When a port connects to another switch, having it in the DSA bridge with STP
# disabled causes broadcast reflection. This corrupts the neighbor's MAC table.
# These functions isolate a port (remove from bridge, assign IP) and restore it
# after flashing is complete.
[ -n "$_CONWRT_BRIDGE_LOADED" ] && return 0
_CONWRT_BRIDGE_LOADED=1

# Isolate a port from the DSA bridge for TFTP access
# Removes the port from the bridge, flushes any existing IPs, assigns a new IP
# Usage: conwrt_bridge_isolate_port PORT IP_ADDR [CIDR]
#   PORT     - e.g. "lan8"
#   IP_ADDR  - IP to assign, e.g. "192.168.1.2"
#   CIDR     - subnet mask, default "24"
conwrt_bridge_isolate_port() {
    _port="$1"
    _ip="$2"
    _cidr="${3:-24}"

    [ -n "$_port" ] || { echo "missing port argument" >&2; return 1; }
    [ -n "$_ip" ] || { echo "missing ip argument" >&2; return 1; }

    _master=$(ip link show "$_port" 2>/dev/null | grep -o 'master [^ ]*' | awk '{print $2}')
    if [ -z "$_master" ]; then
        echo "$_port already isolated"
    else
        echo "isolating $_port from bridge..."
        ip link set dev "$_port" nomaster || {
            echo "failed to remove $_port from bridge" >&2
            return 1
        }
    fi

    ip addr flush dev "$_port" 2>/dev/null
    ip addr add "${_ip}/${_cidr}" dev "$_port" || {
        echo "failed to assign ${_ip}/${_cidr} to $_port" >&2
        return 1
    }
    ip link set dev "$_port" up 2>/dev/null

    echo "$_port isolated with IP ${_ip}/${_cidr}"
    return 0
}

# Restore a port back to the DSA bridge
# Removes any standalone IP, re-adds to the bridge and VLAN
# Usage: conwrt_bridge_restore_port PORT [BRIDGE] [VLAN_ID]
#   PORT     - e.g. "lan8"
#   BRIDGE   - bridge name, default "switch"
#   VLAN_ID  - VLAN ID, default "1"
conwrt_bridge_restore_port() {
    _port="$1"
    _bridge="${2:-switch}"
    _vlan="${3:-1}"

    [ -n "$_port" ] || { echo "missing port argument" >&2; return 1; }

    _master=$(ip link show "$_port" 2>/dev/null | grep -o 'master [^ ]*' | awk '{print $2}')
    if [ "$_master" = "$_bridge" ]; then
        echo "$_port already in $_bridge"
        return 0
    fi

    echo "restoring $_port to $_bridge VLAN $_vlan..."

    ip addr flush dev "$_port" 2>/dev/null

    ip link set dev "$_port" master "$_bridge" || {
        echo "failed to add $_port to $_bridge" >&2
        return 1
    }

    bridge vlan add dev "$_port" vid "$_vlan" "$_bridge" 2>/dev/null || true

    ip link set dev "$_port" up 2>/dev/null

    echo "$_port restored to $_bridge"
    return 0
}

# Check if a port is currently isolated (not a bridge member)
# Usage: conwrt_bridge_is_isolated PORT
# Returns 0 if isolated, 1 if in a bridge
conwrt_bridge_is_isolated() {
    _port="$1"
    _master=$(ip link show "$_port" 2>/dev/null | grep -o 'master [^ ]*' | awk '{print $2}')
    [ -z "$_master" ]
}
