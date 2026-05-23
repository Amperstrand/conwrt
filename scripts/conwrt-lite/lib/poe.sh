#!/bin/sh
# conwrt-lite poe library — PoE port control
[ -n "$_CONWRT_POE_LOADED" ] && return 0
_CONWRT_POE_LOADED=1

conwrt_poe_disable() {
    _port="$1"
    ubus call poe set_port_config "{\"port\":\"$_port\",\"enable\":false}" || {
        echo "failed to disable poe on $_port" >&2
        return 1
    }
    echo "poe disabled on $_port"
    return 0
}

conwrt_poe_enable() {
    _port="$1"
    ubus call poe set_port_config "{\"port\":\"$_port\",\"enable\":true}" || {
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
