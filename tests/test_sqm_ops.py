"""Characterization tests for sqm.py ops pipeline.

render_shell(_build_sqm_ops(...)) is the authoritative output.
If ops change, these tests must be updated to match.
"""
from profile.ops import render_shell
from use_cases.sqm import _build_sqm_ops


DEFAULT_PARAMS = {"download_kbps": 340000, "upload_kbps": 19000}
CUSTOM_PARAMS = {
    "download_kbps": 100000,
    "upload_kbps": 50000,
    "interface": "eth1",
    "qdisc": "fq_codel",
    "script": "layer_cake.qos",
    "link_layer": "ethernet",
    "overhead": 44,
}

EXPECTED_DEFAULT = (
    '# --- SQM Smart Queue Management ---' '\n'
    "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true" '\n'
    '\n'
    '_sqm_dev=$(uci get network.wan.device 2>/dev/null); if [ -z "$_sqm_dev" ] || ! ip addr show "$_sqm_dev" 2>/dev/null | grep -q "inet "; then _sqm_dev=$(ip route show default 0.0.0.0/0 2>/dev/null | awk \'{print $5}\' | head -1); fi; if [ -z "$_sqm_dev" ]; then _sqm_dev=wan; fi' '\n'
    'uci set sqm.wan=queue' '\n'
    'uci set sqm.wan.interface="$_sqm_dev"' '\n'
    "uci set sqm.wan.enabled='1'" '\n'
    "uci set sqm.wan.script='piece_of_cake.qos'" '\n'
    "uci set sqm.wan.qdisc='cake'" '\n'
    "uci set sqm.wan.linklayer='none'" '\n'
    "uci set sqm.wan.overhead='0'" '\n'
    "uci set sqm.wan.download='340000'" '\n'
    "uci set sqm.wan.upload='19000'" '\n'
    "uci set sqm.wan.linklayer_adaptation_mechanism='default'" '\n'
    "uci set sqm.wan.debug_logging='0'" '\n'
    "uci set sqm.wan.verbosity='5'" '\n'
    'uci commit sqm' '\n'
    '\n'
    '/etc/init.d/sqm enable' '\n'
    '/etc/init.d/sqm restart' '\n'
    'echo "SQM configured: 340000/19000 kbit/s (cake) on $_sqm_dev"'
)

EXPECTED_CUSTOM = (
    '# --- SQM Smart Queue Management ---' '\n'
    "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true" '\n'
    '\n'
    '_sqm_dev=$(uci get network.eth1.device 2>/dev/null); if [ -z "$_sqm_dev" ] || ! ip addr show "$_sqm_dev" 2>/dev/null | grep -q "inet "; then _sqm_dev=$(ip route show default 0.0.0.0/0 2>/dev/null | awk \'{print $5}\' | head -1); fi; if [ -z "$_sqm_dev" ]; then _sqm_dev=eth1; fi' '\n'
    'uci set sqm.eth1=queue' '\n'
    'uci set sqm.eth1.interface="$_sqm_dev"' '\n'
    "uci set sqm.eth1.enabled='1'" '\n'
    "uci set sqm.eth1.script='layer_cake.qos'" '\n'
    "uci set sqm.eth1.qdisc='fq_codel'" '\n'
    "uci set sqm.eth1.linklayer='ethernet'" '\n'
    "uci set sqm.eth1.overhead='44'" '\n'
    "uci set sqm.eth1.download='100000'" '\n'
    "uci set sqm.eth1.upload='50000'" '\n'
    "uci set sqm.eth1.linklayer_adaptation_mechanism='default'" '\n'
    "uci set sqm.eth1.debug_logging='0'" '\n'
    "uci set sqm.eth1.verbosity='5'" '\n'
    'uci commit sqm' '\n'
    '\n'
    '/etc/init.d/sqm enable' '\n'
    '/etc/init.d/sqm restart' '\n'
    'echo "SQM configured: 100000/50000 kbit/s (fq_codel) on $_sqm_dev"'
)

EXPECTED_MINIMAL = (
    '# --- SQM Smart Queue Management ---' '\n'
    "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true" '\n'
    '\n'
    '_sqm_dev=$(uci get network.wan.device 2>/dev/null); if [ -z "$_sqm_dev" ] || ! ip addr show "$_sqm_dev" 2>/dev/null | grep -q "inet "; then _sqm_dev=$(ip route show default 0.0.0.0/0 2>/dev/null | awk \'{print $5}\' | head -1); fi; if [ -z "$_sqm_dev" ]; then _sqm_dev=wan; fi' '\n'
    'uci set sqm.wan=queue' '\n'
    'uci set sqm.wan.interface="$_sqm_dev"' '\n'
    "uci set sqm.wan.enabled='1'" '\n'
    "uci set sqm.wan.script='piece_of_cake.qos'" '\n'
    "uci set sqm.wan.qdisc='cake'" '\n'
    "uci set sqm.wan.linklayer='none'" '\n'
    "uci set sqm.wan.overhead='0'" '\n'
    "uci set sqm.wan.download='1'" '\n'
    "uci set sqm.wan.upload='1'" '\n'
    "uci set sqm.wan.linklayer_adaptation_mechanism='default'" '\n'
    "uci set sqm.wan.debug_logging='0'" '\n'
    "uci set sqm.wan.verbosity='5'" '\n'
    'uci commit sqm' '\n'
    '\n'
    '/etc/init.d/sqm enable' '\n'
    '/etc/init.d/sqm restart' '\n'
    'echo "SQM configured: 1/1 kbit/s (cake) on $_sqm_dev"'
)

EXPECTED_MAX_OVERHEAD = (
    '# --- SQM Smart Queue Management ---' '\n'
    "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true" '\n'
    '\n'
    '_sqm_dev=$(uci get network.wan.device 2>/dev/null); if [ -z "$_sqm_dev" ] || ! ip addr show "$_sqm_dev" 2>/dev/null | grep -q "inet "; then _sqm_dev=$(ip route show default 0.0.0.0/0 2>/dev/null | awk \'{print $5}\' | head -1); fi; if [ -z "$_sqm_dev" ]; then _sqm_dev=wan; fi' '\n'
    'uci set sqm.wan=queue' '\n'
    'uci set sqm.wan.interface="$_sqm_dev"' '\n'
    "uci set sqm.wan.enabled='1'" '\n'
    "uci set sqm.wan.script='piece_of_cake.qos'" '\n'
    "uci set sqm.wan.qdisc='cake'" '\n'
    "uci set sqm.wan.linklayer='none'" '\n'
    "uci set sqm.wan.overhead='512'" '\n'
    "uci set sqm.wan.download='100'" '\n'
    "uci set sqm.wan.upload='100'" '\n'
    "uci set sqm.wan.linklayer_adaptation_mechanism='default'" '\n'
    "uci set sqm.wan.debug_logging='0'" '\n'
    "uci set sqm.wan.verbosity='5'" '\n'
    'uci commit sqm' '\n'
    '\n'
    '/etc/init.d/sqm enable' '\n'
    '/etc/init.d/sqm restart' '\n'
    'echo "SQM configured: 100/100 kbit/s (cake) on $_sqm_dev"'
)


class TestSqmOps:
    def test_default_params(self):
        assert render_shell(_build_sqm_ops(DEFAULT_PARAMS)) == EXPECTED_DEFAULT

    def test_custom_params(self):
        assert render_shell(_build_sqm_ops(CUSTOM_PARAMS)) == EXPECTED_CUSTOM

    def test_minimal_speeds(self):
        params = {"download_kbps": 1, "upload_kbps": 1}
        assert render_shell(_build_sqm_ops(params)) == EXPECTED_MINIMAL

    def test_max_overhead(self):
        params = {"download_kbps": 100, "upload_kbps": 100, "overhead": 512}
        assert render_shell(_build_sqm_ops(params)) == EXPECTED_MAX_OVERHEAD
