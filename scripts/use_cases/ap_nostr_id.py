"""ap-nostr-id -- Generate a Nostr keypair per AP and write npub as hostapd nas_identifier."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ShellCommand, UciCommit, render_shell

from . import ParamDef, UseCase, register

_NPUB_PREFIX = "npub1"
_NSEC_PREFIX = "nsec1"


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    npub = str(params.get("npub", ""))
    nsec = str(params.get("nsec", ""))

    if npub and not npub.startswith(_NPUB_PREFIX):
        raise ValueError(f"npub must start with '{_NPUB_PREFIX}'")
    if nsec and not nsec.startswith(_NSEC_PREFIX):
        raise ValueError(f"nsec must start with '{_NSEC_PREFIX}'")
    if (npub and not nsec) or (nsec and not npub):
        raise ValueError("npub and nsec must both be provided or both be empty")

    if not npub or not nsec:
        from generate_nostr_keypair import generate_keypair
        nsec, npub = generate_keypair()

    return {"npub": npub, "nsec": nsec}


def _build_ap_nostr_id_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    npub = r["npub"]
    nsec = r["nsec"]

    ops: list[Op] = [
        Comment(text="--- AP Nostr identity ---"),
        ShellCommand(command="mkdir -p /etc/tollgate"),
        ShellCommand(
            command=f"[ -f /etc/tollgate/ap-nsec ]"
            f" || printf '%s\\n' '{nsec}' > /etc/tollgate/ap-nsec"
        ),
        ShellCommand(command="[ -f /etc/tollgate/ap-nsec ] || chmod 600 /etc/tollgate/ap-nsec"),
        ShellCommand(
            command=f"[ -f /etc/tollgate/ap-npub ]"
            f" || printf '%s\\n' '{npub}' > /etc/tollgate/ap-npub"
        ),
        ShellCommand(command="[ -f /etc/tollgate/ap-npub ] || chmod 644 /etc/tollgate/ap-npub"),
        BlankLine(),
        Comment(text="--- Set nas_identifier on all wifi-iface sections ---"),
        ShellCommand(
            command="for _s in $(uci show wireless 2>/dev/null | grep '=wifi-iface'"
            " | cut -d. -f2 | cut -d= -f1); do"
            f" uci set wireless.$_s.nas_identifier='{npub}';"
            " done"
        ),
        UciCommit(config="wireless"),
        ShellCommand(command="wifi reload 2>/dev/null || true"),
        ShellCommand(command=f'echo "AP Nostr identity configured: npub={npub[:24]}..."'),
    ]

    return ops


register(UseCase(
    name="ap-nostr-id",
    description=(
        "Generate a Nostr keypair per access point. "
        "Writes npub as hostapd nas_identifier so RADIUS requests self-identify the AP, "
        "and saves nsec to /etc/tollgate/ap-nsec for future use."
    ),
    packages=[],
    params={
        "npub": ParamDef(type=str, default="",
            description="Pre-generated npub (bech32, starts with npub1). Auto-generated if empty."),
        "nsec": ParamDef(type=str, default="",
            description="Pre-generated nsec (bech32, starts with nsec1). Auto-generated if empty."),
    },
    build_configure=lambda p: render_shell(_build_ap_nostr_id_ops(p)),
    build_configure_ops=_build_ap_nostr_id_ops,
    configure_via="ssh",
    requires_capabilities=["ethernet"],
    test_status="untested",
))
