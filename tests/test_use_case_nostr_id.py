"""Tests for the ap-nostr-id use case."""
from __future__ import annotations

import pytest

from use_cases import get
from generate_nostr_keypair import generate_keypair, bech32_decode, convertbits

_TEST_NSEC = "nsec1jt6qv89h8usuxa32cgh27nwlef8ua5r8yvhrj3u6wkatam4wfy0qflw0ch"
_TEST_NPUB = "npub1q03x4aa0y2ct287uf5qfhccke9x6zjm07shr2c04w3q5w8qln0g5ykugtm6"


def test_use_case_is_registered() -> None:
    uc = get("ap-nostr-id")
    assert uc is not None
    assert uc.name == "ap-nostr-id"
    assert uc.configure_via == "ssh"
    assert uc.packages == []
    assert uc.test_status == "untested"


def test_build_configure_with_provided_params() -> None:
    uc = get("ap-nostr-id")
    assert uc is not None
    out = uc.build_configure({"npub": _TEST_NPUB, "nsec": _TEST_NSEC})
    assert isinstance(out, str)
    assert "/etc/tollgate/ap-nsec" in out
    assert "/etc/tollgate/ap-npub" in out
    assert "chmod 600" in out
    assert "chmod 644" in out
    assert "nas_identifier" in out
    assert _TEST_NSEC in out
    assert _TEST_NPUB in out


def test_nas_identifier_set_to_npub_value() -> None:
    uc = get("ap-nostr-id")
    assert uc is not None
    out = uc.build_configure({"npub": _TEST_NPUB, "nsec": _TEST_NSEC})
    assert f"nas_identifier='{_TEST_NPUB}'" in out


def test_wifi_iface_iteration_pattern() -> None:
    uc = get("ap-nostr-id")
    assert uc is not None
    out = uc.build_configure({"npub": _TEST_NPUB, "nsec": _TEST_NSEC})
    assert "grep '=wifi-iface'" in out
    assert "uci show wireless" in out
    assert "uci commit wireless" in out


def test_does_not_overwrite_existing_keys() -> None:
    uc = get("ap-nostr-id")
    assert uc is not None
    out = uc.build_configure({"npub": _TEST_NPUB, "nsec": _TEST_NSEC})
    assert "[ -f /etc/tollgate/ap-nsec ] ||" in out
    assert "[ -f /etc/tollgate/ap-npub ] ||" in out


def test_wifi_reload_at_end() -> None:
    uc = get("ap-nostr-id")
    assert uc is not None
    out = uc.build_configure({"npub": _TEST_NPUB, "nsec": _TEST_NSEC})
    assert "wifi reload" in out


def test_param_validation_rejects_npub_without_prefix() -> None:
    from use_cases.ap_nostr_id import _resolve_params
    with pytest.raises(ValueError, match="npub must start with 'npub1'"):
        _resolve_params({"npub": "bad_prefix123", "nsec": _TEST_NSEC})


def test_param_validation_rejects_nsec_without_prefix() -> None:
    from use_cases.ap_nostr_id import _resolve_params
    with pytest.raises(ValueError, match="nsec must start with 'nsec1'"):
        _resolve_params({"npub": _TEST_NPUB, "nsec": "bad_prefix456"})


def test_param_validation_rejects_partial_pair() -> None:
    from use_cases.ap_nostr_id import _resolve_params
    with pytest.raises(ValueError, match="both be provided or both be empty"):
        _resolve_params({"npub": _TEST_NPUB, "nsec": ""})
    with pytest.raises(ValueError, match="both be provided or both be empty"):
        _resolve_params({"npub": "", "nsec": _TEST_NSEC})


def test_auto_generate_keypair_when_params_empty() -> None:
    from use_cases.ap_nostr_id import _resolve_params
    r = _resolve_params({})
    assert r["npub"].startswith("npub1")
    assert r["nsec"].startswith("nsec1")
    assert len(r["npub"]) > 30
    assert len(r["nsec"]) > 30


def test_auto_generated_keypair_is_valid() -> None:
    from use_cases.ap_nostr_id import _resolve_params
    r = _resolve_params({})
    _, nsec_data = bech32_decode(r["nsec"])
    priv_bytes = bytes(convertbits(nsec_data, 5, 8, pad=False))
    assert len(priv_bytes) == 32

    _, npub_data = bech32_decode(r["npub"])
    pub_bytes = bytes(convertbits(npub_data, 5, 8, pad=False))
    assert len(pub_bytes) == 33
    assert pub_bytes[0] in (0x02, 0x03)


def test_build_configure_deterministic_with_provided_params() -> None:
    uc = get("ap-nostr-id")
    assert uc is not None
    params = {"npub": _TEST_NPUB, "nsec": _TEST_NSEC}
    out1 = uc.build_configure(params)
    out2 = uc.build_configure(params)
    assert out1 == out2


def test_generate_keypair_produces_valid_output() -> None:
    nsec, npub = generate_keypair()
    assert nsec.startswith("nsec1")
    assert npub.startswith("npub1")
    _, nsec_data = bech32_decode(nsec)
    priv_bytes = bytes(convertbits(nsec_data, 5, 8, pad=False))
    assert len(priv_bytes) == 32
    _, npub_data = bech32_decode(npub)
    pub_bytes = bytes(convertbits(npub_data, 5, 8, pad=False))
    assert len(pub_bytes) == 33
    assert pub_bytes[0] in (0x02, 0x03)
