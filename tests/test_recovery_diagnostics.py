"""Hardware-free checks for recovery-probe page classification, boot-watch
packet classification, preflight stale-ip downgrade, and webkit multipart
framing. No network calls (curl/ip are only exercised via subprocess in the
command layer, not here)."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

from conwrt.cmd_recovery_probe import classify_recovery_page  # noqa: E402
from conwrt.cmd_boot_watch import classify_packet_line  # noqa: E402
from flash.upload import build_webkit_multipart  # noqa: E402
from flash.preflight import _check_stale_ip  # noqa: E402
from types import SimpleNamespace  # noqa: E402


RECOVERY_HTML = (
    "<!DOCTYPE html><html><head></head><body>"
    "<center>D-Link Router Recovery Mode</center>"
    "<span>Upgrade successfully!</span></body></html>"
)
STOCK_HTML = (
    "<!DOCTYPE html><html><head><title>D-LINK</title></head>"
    "<body>HNAP1 login</body></html>"
)


def test_classify_recovery_page() -> None:
    state, _ = classify_recovery_page(RECOVERY_HTML)
    assert state == "recovery"
    state, _ = classify_recovery_page(STOCK_HTML)
    assert state == "stock"
    state, _ = classify_recovery_page("")
    assert state == "silent"
    state, detail = classify_recovery_page("<!DOCTYPE html><p>mystery</p>")
    assert state == "html" and detail


def test_classify_packet_line() -> None:
    mld = ("19:45:34.893593 b8:22:28:aa:bb:cc > 33:33:00:00:00:01, "
           "ethertype IPv6 (0x86dd), length 90: fe80::... > ff02::16: "
           "ICMP6, multicast listener report, v2")
    assert "mld" in (tag := classify_packet_line(mld) or "")
    dhcp = ("19:45:35.100000 b8:22:28:aa:bb:cc > ff:ff:ff:ff:ff:ff, "
            "ethertype IPv4 (0x0800), length 576: 0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP")
    assert classify_packet_line(dhcp) == "dhcp"
    arp = ("19:45:36.200000 b8:22:28:aa:bb:cc > ff:ff:ff:ff:ff:ff, "
           "ethertype ARP (0x0806), length 42: Request who-has 192.168.1.254 tell 192.168.1.1")
    assert classify_packet_line(arp) == "arp"
    assert classify_packet_line("tcpdump: verbose output suppressed") is None
    assert classify_packet_line("") is None


def test_check_stale_ip_downgrades_exact_client_ip() -> None:
    import flash.preflight as pf
    profile = SimpleNamespace(client_ip="192.168.0.10", openwrt_client_ip="192.168.1.254")
    original = pf.get_interface_ips
    try:
        pf.get_interface_ips = lambda iface: ["192.168.0.10"]
        result = _check_stale_ip("br-lan.401", profile)
        assert result.status == "warn"
        pf.get_interface_ips = lambda iface: ["10.0.0.99"]
        result = _check_stale_ip("br-lan.401", profile)
        assert result.status == "pass"
    finally:
        pf.get_interface_ips = original


def test_build_webkit_multipart_framing(tmp_path: Path) -> None:
    img = tmp_path / "fw.bin"
    payload = bytes(range(256)) * 4
    img.write_bytes(payload)
    body, ctype = build_webkit_multipart(str(img), "firmware")
    assert ctype.startswith("multipart/form-data; boundary=----WebKitFormBoundary")
    token = ctype.split("boundary=")[1].encode()
    assert body.count(b"--" + token) == 2
    assert body.count(b"\r\n") >= 4
    assert b'name="firmware"; filename="fw.bin"' in body
    assert b"Content-Type: application/octet-stream\r\n\r\n" in body
    assert payload in body
    assert body.endswith(b"--" + token + b"--\r\n")
