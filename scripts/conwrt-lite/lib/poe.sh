#!/bin/sh
# conwrt-lite poe library — PoE port control
[ -n "$_CONWRT_POE_LOADED" ] && return 0
_CONWRT_POE_LOADED=1

conwrt_poe_disable() {
    _port="$1"
    # Runtime power control via manage (NOT set_port_config which is UCI/persistent).
    # set_port_config + restart does NOT cut power — only manage works for runtime.
    # Action names are "disable"/"enable", NOT "off"/"on".
    ubus call poe manage "{\"port\":\"$_port\",\"action\":\"disable\"}" || {
        echo "failed to disable poe on $_port" >&2
        return 1
    }
    echo "poe disabled on $_port"
    return 0
}

conwrt_poe_enable() {
    _port="$1"
    ubus call poe manage "{\"port\":\"$_port\",\"action\":\"enable\"}" || {
        echo "failed to enable poe on $_port" >&2
        return 1
    }
    echo "poe enabled on $_port"
    return 0
}

conwrt_poe_wait() {
    _seconds="$1"
    echo "waiting ${_seconds}s for poe device..."
    sleep "$_seconds"
}
