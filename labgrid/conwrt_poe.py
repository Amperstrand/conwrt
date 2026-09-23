"""conwrt_poe — labgrid power backend for the Amperstrand realtek-poe fork.

Backend for NetworkPowerDriver / NetworkPowerPort (model: conwrt_poe).
Controls PoE ports on an OpenWrt bench switch running the fork at
github.com/Amperstrand/realtek-poe (ai-experiments), whose ubus API is:

    ubus call poe manage {"port":"lanN","action":"enable"|"disable"}
    ubus call poe info          -> {"ports":{"lanN":{"status":"...",
                                                  "consumption": watts}}}

The stock labgrid `ubus` backend sends {"enable": bool} over HTTP-ubus —
incompatible with this fork and requires uhttpd-mod-ubus; this backend
speaks the fork's native action-form over SSH instead. Long-term fix
(pattern doc): patch the fork to accept enable-bools + uhttpd ACL, then
switch to the stock backend.

power_set is VERIFIED (semantics ported from tollgate-lab's PoePowerController,
with permission): a wedged realtek-poe daemon keeps answering `poe info` with
a frozen per-port snapshot while silently dropping manage calls — observed
live twice (manage rc=0, port state never changed). After every manage the
backend polls until the port reflects the requested state and raises on a
frozen snapshot or a timeout. Never restart the poe service from tooling to
"fix" a wedge — that power-blips every PD on the switch; take the bench lock
and coordinate first.

Poll-lag tolerance (T23, 2026-09-23): a HEALTHY manage's status readback can
lag by up to ~30s (MCU settle under load) — during that settling window a
frozen-looking digest is NOT wedge evidence. Wedge judgment (DROPPED) only
starts after SETTLING_S; a state that never matches raises UNVERIFIED at
VERIFY_TIMEOUT_S.

SSH sessions are multiplexed through a ControlMaster socket (30s persist)
so repeated polls reuse one authenticated connection.

Install: copy this file into the labgrid install on the driver host:
    ~/.local/lib/python3.12/site-packages/labgrid/driver/power/conwrt_poe.py
(the exporter host also keeps a staging copy at ~/conwrt-labgrid/conwrt_poe.py
— refresh or remove it so it cannot drift back in).
Source of truth: conwrt repo, labgrid/conwrt_poe.py
(reinstall after labgrid upgrades AND after editing this file)
"""

from __future__ import annotations

import json
import subprocess
import time

SSH_OPTS = [
    "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ControlMaster=auto",
    "-o", "ControlPath=/tmp/conwrt-poe-%r@%h:%p",
    "-o", "ControlPersist=30s",
]
OFF_STATES = {"disabled", "off", "", "fault"}
TRANSIENT_STATES = {"initializing", "unknown"}
SETTLING_S = 35.0
VERIFY_TIMEOUT_S = 60.0
FROZEN_GRACE_S = 6.0
POLL_INTERVAL_S = 0.8


def _ssh(host: str, command: str) -> str:
    proc = subprocess.run(
        ["ssh", *SSH_OPTS, f"root@{host}", command],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"switch ssh failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _reject_port_arg(port: str | None) -> None:
    if port is not None:
        raise RuntimeError(
            "conwrt_poe addresses ports by index only — remove the 'port:' "
            "key from the NetworkPowerPort exporter entry (the fork's "
            "action-string ubus API takes lan<index>)")


def _port_snapshot(host: str, index: int) -> tuple[str, float]:
    raw = _ssh(host, "ubus call poe info")
    entry = json.loads(raw)["ports"].get(f"lan{index}")
    if entry is None:
        raise RuntimeError(f"port lan{index} not in poe info")
    if isinstance(entry, dict):
        status = str(entry.get("status", "unknown")).strip().lower()
        try:
            watts = float(entry.get("consumption", 0.0))
        except (TypeError, ValueError):
            watts = 0.0
    else:
        status, watts = str(entry).strip().lower(), 0.0
    return status, watts


def _verify_manage(host: str, index: int, want_disabled: bool) -> None:
    started = time.monotonic()
    deadline = started + VERIFY_TIMEOUT_S
    frozen_since: float | None = None
    last_digest: str | None = None
    last_state = ""
    while time.monotonic() < deadline:
        last_state, watts = _port_snapshot(host, index)
        disabled = last_state in OFF_STATES
        if disabled == want_disabled and last_state not in TRANSIENT_STATES:
            return
        digest = f"{last_state}:{watts:.3f}"
        now = time.monotonic()
        if now - started < SETTLING_S:
            # T23: a healthy readback lags up to ~30s — a frozen digest
            # inside the settling window is not evidence of a wedge.
            frozen_since = None
        elif digest == last_digest:
            if frozen_since is None:
                frozen_since = now
            elif now - frozen_since > FROZEN_GRACE_S:
                raise RuntimeError(
                    f"poe manage DROPPED: lan{index} snapshot frozen at "
                    f"'{last_state}' ({watts:.1f}W) for "
                    f">{FROZEN_GRACE_S:.0f}s past the {SETTLING_S:.0f}s "
                    "readback-lag window after a successful manage call — "
                    "wedged daemon (daemon<->MCU link). Do NOT restart the "
                    "poe service from tooling: it power-blips every PD; take "
                    "the bench lock and coordinate, then restart "
                    "/etc/init.d/poe manually.")
        else:
            frozen_since = None
        last_digest = digest
        time.sleep(POLL_INTERVAL_S)
    raise RuntimeError(
        f"poe manage UNVERIFIED: lan{index} still '{last_state}' after "
        f"{VERIFY_TIMEOUT_S:.0f}s (wanted "
        f"{'disabled-class' if want_disabled else 'active-class'})")


def power_set(host: str, port: str | None, index: int, value: int) -> None:
    _reject_port_arg(port)
    action = "enable" if value else "disable"
    _ssh(host, f"ubus call poe manage '{{\"port\":\"lan{index}\","
               f"\"action\":\"{action}\"}}'")
    # The fork's manage is silently successful even when dropped — verify.
    # _verify_manage tolerates the ~30s status-readback lag (SETTLING_S)
    # before judging a frozen snapshot a wedge.
    _verify_manage(host, index, want_disabled=not value)


def power_get(host: str, port: str | None, index: int) -> bool:
    _reject_port_arg(port)
    status, _watts = _port_snapshot(host, index)
    return status not in OFF_STATES
