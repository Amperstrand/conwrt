"""Characterization tests for tollgate_security.py ops.

render_shell(_build_security_ops(...)) is the authoritative output.
No params, no interpolation — the four firewall rules are named
sections (idempotent re-set) and WiFi isolation is two typed uci sets.
"""
from profile.ops import render_shell
from use_cases.tollgate_security import _build_security_ops


EXPECTED = (
    "# --- TollGate Security: RFC 1918 isolation ---\n"
    "uci set firewall.Block-LAN-To-RFC1918-10=rule\n"
    "uci set firewall.Block-LAN-To-RFC1918-10.name='Block-LAN-To-RFC1918-10'\n"
    "uci set firewall.Block-LAN-To-RFC1918-10.src='lan'\n"
    "uci set firewall.Block-LAN-To-RFC1918-10.dest='wan'\n"
    "uci set firewall.Block-LAN-To-RFC1918-10.dest_ip='10.0.0.0/8'\n"
    "uci set firewall.Block-LAN-To-RFC1918-10.proto='all'\n"
    "uci set firewall.Block-LAN-To-RFC1918-10.family='ipv4'\n"
    "uci set firewall.Block-LAN-To-RFC1918-10.target='DROP'\n"
    "#   Block-LAN-To-RFC1918-10: RFC 1918 private (class A)\n"
    "uci set firewall.Block-LAN-To-RFC1918-172=rule\n"
    "uci set firewall.Block-LAN-To-RFC1918-172.name='Block-LAN-To-RFC1918-172'\n"
    "uci set firewall.Block-LAN-To-RFC1918-172.src='lan'\n"
    "uci set firewall.Block-LAN-To-RFC1918-172.dest='wan'\n"
    "uci set firewall.Block-LAN-To-RFC1918-172.dest_ip='172.16.0.0/12'\n"
    "uci set firewall.Block-LAN-To-RFC1918-172.proto='all'\n"
    "uci set firewall.Block-LAN-To-RFC1918-172.family='ipv4'\n"
    "uci set firewall.Block-LAN-To-RFC1918-172.target='DROP'\n"
    "#   Block-LAN-To-RFC1918-172: RFC 1918 private (class B)\n"
    "uci set firewall.Block-LAN-To-RFC1918-192=rule\n"
    "uci set firewall.Block-LAN-To-RFC1918-192.name='Block-LAN-To-RFC1918-192'\n"
    "uci set firewall.Block-LAN-To-RFC1918-192.src='lan'\n"
    "uci set firewall.Block-LAN-To-RFC1918-192.dest='wan'\n"
    "uci set firewall.Block-LAN-To-RFC1918-192.dest_ip='192.168.0.0/16'\n"
    "uci set firewall.Block-LAN-To-RFC1918-192.proto='all'\n"
    "uci set firewall.Block-LAN-To-RFC1918-192.family='ipv4'\n"
    "uci set firewall.Block-LAN-To-RFC1918-192.target='DROP'\n"
    "#   Block-LAN-To-RFC1918-192: RFC 1918 private (class C — ISP router LAN)\n"
    "uci set firewall.Block-LAN-To-RFC1918-LL=rule\n"
    "uci set firewall.Block-LAN-To-RFC1918-LL.name='Block-LAN-To-RFC1918-LL'\n"
    "uci set firewall.Block-LAN-To-RFC1918-LL.src='lan'\n"
    "uci set firewall.Block-LAN-To-RFC1918-LL.dest='wan'\n"
    "uci set firewall.Block-LAN-To-RFC1918-LL.dest_ip='169.254.0.0/16'\n"
    "uci set firewall.Block-LAN-To-RFC1918-LL.proto='all'\n"
    "uci set firewall.Block-LAN-To-RFC1918-LL.family='ipv4'\n"
    "uci set firewall.Block-LAN-To-RFC1918-LL.target='DROP'\n"
    "#   Block-LAN-To-RFC1918-LL: RFC 3927 link-local (mDNS, SSDP)\n"
    "uci commit firewall\n"
    "/etc/init.d/firewall restart\n"
    "# --- WiFi client isolation ---\n"
    "for _s in $(uci show wireless 2>/dev/null | grep '=wifi-iface' "
    "| cut -d. -f2 | cut -d= -f1); do "
    "uci set wireless.$_s.isolate='1'; done; true\n"
    "uci commit wireless\n"
    "wifi reload"
)


class TestTollgateSecurityOps:
    def test_full_render(self):
        assert render_shell(_build_security_ops({})) == EXPECTED

    def test_rules_are_named_sections(self):
        # named sections re-set in place — no anonymous-section
        # accumulation on re-configure
        rendered = render_shell(_build_security_ops({}))
        assert "uci add firewall" not in rendered

    def test_router_output_chain_untouched(self):
        rendered = render_shell(_build_security_ops({}))
        assert "OUTPUT" not in rendered

    def test_activation_ops_present(self):
        # regression (Codex #601 P1): committed UCI alone left the
        # running firewall open until a later reload — the apply now
        # activates both halves before reporting success
        rendered = render_shell(_build_security_ops({}))
        assert "/etc/init.d/firewall restart" in rendered
        assert "wifi reload" in rendered

    def test_isolation_discovers_ifaces_not_hardcoded_radios(self):
        # regression (Codex #601 P2 round 2): hardcoded
        # default_radio0/default_radio1 aborted mid-apply on
        # single-radio devices — isolation now targets every existing
        # wifi-iface section, whatever it is named
        rendered = render_shell(_build_security_ops({}))
        assert "default_radio0" not in rendered
        assert "default_radio1" not in rendered
        assert "uci set wireless.$_s.isolate='1'" in rendered
