"""Characterization + defect-regression tests for vpn_node.py.

The charset gates and the d_tag determinism fix landed with the Rust
port (plan.rs VpnNodeProfile) — the surfshark #604 class applied
proactively, plus a 1.x non-determinism defect (timestamp d_tag).
"""
import pytest
from profile.ops import render_shell
from use_cases.vpn_node import _build_vpn_node_ops


NSECS = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PARAMS: dict = {"nsec": NSECS, "endpoint_host": "vpn.example.com"}


class TestVpnNodeOps:
    def test_transport_shape(self):
        rendered = render_shell(_build_vpn_node_ops(PARAMS))
        assert "cat > /etc/vpn-listing.sh << 'SCRIPT'" in rendered
        assert "-k 30402" in rendered
        assert '-d "vpn-node"' in rendered
        assert '-t "region=US"' in rendered
        assert '-t "price=50sat/hour"' in rendered
        assert f"echo '{NSECS}' > /etc/vpn-node/nsec" in rendered
        assert "chmod 600 /etc/vpn-node/nsec" in rendered
        assert "( sleep 30 && /etc/vpn-listing.sh > /tmp/vpn-listing.log 2>&1 ) &" in rendered

    def test_listing_json_carries_endpoint(self):
        rendered = render_shell(_build_vpn_node_ops(PARAMS))
        assert '\\"endpoint\\":\\"vpn.example.com:51820\\"' in rendered or \
            '"endpoint":"vpn.example.com:51820"' in rendered.replace("\\", "")

    def test_deterministic_output(self):
        # regression: the 1.x d_tag fallback was a timestamp — direct
        # calls differed every run (golden-hostile)
        a = render_shell(_build_vpn_node_ops(PARAMS))
        b = render_shell(_build_vpn_node_ops(PARAMS))
        assert a == b
        assert '-d "vpn-node"' in a  # the declared default, not vpn-<ts>


class TestVpnNodeGates:
    def test_hostile_nsec_rejected(self):
        for evil in ("x'; rm -rf /; '", "abc def", "$(reboot)", "a&b"):
            with pytest.raises(ValueError, match="nsec"):
                _build_vpn_node_ops({**PARAMS, "nsec": evil})

    def test_hostile_title_rejected(self):
        # title lands in BOTH a single-quoted shell arg and a JSON string
        for evil in ("John's VPN", 'Say "hi"', "back\\slash", "a\nb"):
            with pytest.raises(ValueError, match="title"):
                _build_vpn_node_ops({**PARAMS, "title": evil})

    def test_hostile_content_rejected(self):
        with pytest.raises(ValueError, match="content"):
            _build_vpn_node_ops({**PARAMS, "content": "x'; rm -rf /; '"})

    def test_hostile_d_tag_rejected(self):
        with pytest.raises(ValueError, match="d_tag"):
            _build_vpn_node_ops({**PARAMS, "d_tag": 'a"; rm'})

    def test_endpoint_host_validated(self):
        with pytest.raises(Exception, match="endpoint_host"):
            _build_vpn_node_ops({"nsec": NSECS, "endpoint_host": "a; rm -rf /"})
        with pytest.raises(Exception, match="endpoint_host"):
            _build_vpn_node_ops({"nsec": NSECS, "endpoint_host": ""})

    def test_country_two_letters(self):
        for evil in ('s"; rm', "swe", "s-e"):
            with pytest.raises(ValueError, match="country"):
                _build_vpn_node_ops({**PARAMS, "country": evil})

    def test_price_gates(self):
        with pytest.raises(ValueError, match="price_amount"):
            _build_vpn_node_ops({**PARAMS, "price_amount": 0})
        for evil in ("century", "hou r", "hour;rm"):
            with pytest.raises(ValueError, match="price_unit"):
                _build_vpn_node_ops({**PARAMS, "price_unit": evil})

    def test_hostile_relay_rejected(self):
        # relays land as BARE shell words inside the script
        for evil in ("wss://ok.example x", "wss://a;rm", "https://plain.example",
                     "wss://a'rm", "wss://a b"):
            with pytest.raises(ValueError, match="relay"):
                _build_vpn_node_ops({**PARAMS, "relays": evil})

    def test_hostile_nak_path_rejected(self):
        with pytest.raises(ValueError, match="nak_path"):
            _build_vpn_node_ops({**PARAMS, "nak_path": "/usr/bin/nak; rm"})
