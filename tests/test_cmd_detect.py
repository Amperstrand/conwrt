"""Tests for conwrt.cmd_detect (cmd_fingerprint and cmd_auto).

Both are command dispatch wrappers that call into device_detect / auto_detect
and render the results. Tests verify rendering paths, return codes, and
correct argument flow.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


# Ensure scripts/ on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


# ---------------------------------------------------------------------------
# Stub dataclasses matching real FingerprintResult / DeviceCandidate /
# DetectedRouter shapes (only the attrs cmd_detect.py touches).
# ---------------------------------------------------------------------------


@dataclass
class _StubCandidate:
    vendor: str = "Unknown"
    model_id: str | None = None
    confidence: str = "low"
    evidence: list = field(default_factory=list)
    mac_oui: str | None = None
    hostname: str | None = None
    ssh_banner: str | None = None
    open_ports: list = field(default_factory=list)
    board_name: str | None = None


@dataclass
class _StubResult:
    candidates: list = field(default_factory=list)


@dataclass
class _StubMatch:
    vendor: str = ""
    model_id: str = ""
    confidence: str = ""
    evidence: list = field(default_factory=list)


@dataclass
class _StubRouter:
    ip: str = "192.168.1.1"
    mac: str = "aa:bb:cc:dd:ee:ff"
    vendor: str = "TestVendor"
    model_name: str = "TestModel"
    firmware_state: str = "openwrt"
    confidence: str = "high"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_fp_args(ip: str = "192.168.1.1", timeout: float = 10.0,
                  json_output: bool = False):
    return SimpleNamespace(ip=ip, timeout=timeout, json_output=json_output)


def _make_auto_args(interface=None, passive_timeout: int = 10,
                    no_menu: bool = False):
    return SimpleNamespace(
        interface=interface,
        passive_timeout=passive_timeout,
        no_menu=no_menu,
    )


# ===========================================================================
# cmd_fingerprint
# ===========================================================================


class TestCmdFingerprintEmpty:
    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_no_candidates_returns_1(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[])

        result = cmd_fingerprint(_make_fp_args())

        assert result == 1
        captured = capsys.readouterr()
        assert "No device detected" in captured.err
        # No need to call match_models when no candidates
        mock_match.assert_not_called()

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_no_candidates_error_includes_ip(
        self, _log, mock_fp, _mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[])

        cmd_fingerprint(_make_fp_args(ip="10.20.30.40"))

        captured = capsys.readouterr()
        assert "10.20.30.40" in captured.err


class TestCmdFingerprintArgs:
    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_timeout_passed_to_fingerprint(
        self, _log, mock_fp, mock_match,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[_StubCandidate()])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args(timeout=2.5))

        mock_fp.assert_called_once_with("192.168.1.1", timeout=2.5)

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_ip_passed_to_fingerprint(
        self, _log, mock_fp, mock_match,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[_StubCandidate()])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args(ip="172.16.0.1"))

        mock_fp.assert_called_once_with("172.16.0.1", timeout=10.0)


class TestCmdFingerprintHumanRender:
    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_minimal_candidate(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(vendor="D-Link", confidence="high",
                           evidence=["mac_oui"]),
        ])
        mock_match.return_value = []

        result = cmd_fingerprint(_make_fp_args())

        assert result == 0
        out = capsys.readouterr().out
        assert "Vendor: D-Link" in out
        assert "Confidence: high" in out
        assert "Evidence: mac_oui" in out
        assert "No model matches found" in out

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_candidate_without_model_id_skips_model_line(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(vendor="X", model_id=None),
        ])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args())

        out = capsys.readouterr().out
        assert "Model:" not in out

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_candidate_with_model_id_prints_model_line(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(vendor="X", model_id="my-model"),
        ])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args())

        out = capsys.readouterr().out
        assert "Model:  my-model" in out

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_optional_fields_printed_when_set(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(
                vendor="D-Link",
                ssh_banner="SSH-2.0-dropbear",
                open_ports=[22, 80],
                board_name="dlink,covr-x1860-a1",
            ),
        ])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args())

        out = capsys.readouterr().out
        assert "SSH Banner: SSH-2.0-dropbear" in out
        assert "Open Ports: [22, 80]" in out
        assert "Board:      dlink,covr-x1860-a1" in out

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_optional_fields_skipped_when_unset(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(vendor="X"),  # all optional fields None/[]
        ])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args())

        out = capsys.readouterr().out
        assert "SSH Banner:" not in out
        assert "Open Ports:" not in out
        assert "Board:" not in out

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_multiple_candidates_all_printed(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(vendor="A"),
            _StubCandidate(vendor="B"),
            _StubCandidate(vendor="C"),
        ])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args())

        out = capsys.readouterr().out
        assert "Vendor: A" in out
        assert "Vendor: B" in out
        assert "Vendor: C" in out

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_evidence_list_joined_with_comma(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(vendor="X",
                           evidence=["oui", "ssh", "port_22"]),
        ])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args())

        out = capsys.readouterr().out
        assert "Evidence: oui, ssh, port_22" in out


class TestCmdFingerprintHumanMatches:
    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_model_matches_printed(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(vendor="D-Link"),
        ])
        mock_match.return_value = [
            _StubMatch(vendor="D-Link", model_id="m1",
                       confidence="high", evidence=["mac_oui"]),
            _StubMatch(vendor="D-Link", model_id="m2",
                       confidence="medium", evidence=["board_name"]),
        ]

        cmd_fingerprint(_make_fp_args())

        out = capsys.readouterr().out
        assert "Model matches:" in out
        assert "m1 (D-Link) — high confidence" in out
        assert "m2 (D-Link) — medium confidence" in out
        assert "Evidence: mac_oui" in out
        assert "Evidence: board_name" in out

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_no_matches_section_when_empty(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[_StubCandidate()])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args())

        out = capsys.readouterr().out
        assert "Model matches:" not in out
        assert "No model matches found" in out


class TestCmdFingerprintJson:
    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_json_output_structure(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(
                vendor="D-Link", model_id="covr-x1860-a1",
                confidence="high", evidence=["mac_oui", "ssh"],
                mac_oui="1C:69:7A", hostname="dlink-covr",
                ssh_banner="SSH-2.0-OpenSSH", open_ports=[22, 80],
                board_name="dlink,covr-x1860-a1",
            ),
        ])
        mock_match.return_value = [
            _StubMatch(vendor="D-Link", model_id="m1",
                       confidence="high", evidence=["e1"]),
        ]

        result = cmd_fingerprint(_make_fp_args(ip="10.0.0.1", json_output=True))

        assert result == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["ip"] == "10.0.0.1"
        assert len(data["candidates"]) == 1
        c = data["candidates"][0]
        assert c["vendor"] == "D-Link"
        assert c["model_id"] == "covr-x1860-a1"
        assert c["confidence"] == "high"
        assert c["evidence"] == ["mac_oui", "ssh"]
        assert c["mac_oui"] == "1C:69:7A"
        assert c["hostname"] == "dlink-covr"
        assert c["ssh_banner"] == "SSH-2.0-OpenSSH"
        assert c["open_ports"] == [22, 80]
        assert c["board_name"] == "dlink,covr-x1860-a1"

        assert len(data["model_matches"]) == 1
        m = data["model_matches"][0]
        assert m["model_id"] == "m1"
        assert m["evidence"] == ["e1"]

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_json_with_no_matches_returns_empty_list(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[_StubCandidate()])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args(json_output=True))

        data = json.loads(capsys.readouterr().out)
        assert data["model_matches"] == []

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_json_omits_human_readable_output(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(vendor="X"),
        ])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args(json_output=True))

        out = capsys.readouterr().out
        # Human output uses "Vendor: X" with two spaces. JSON wraps in quotes.
        assert "Vendor: X" not in out

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_json_handles_none_fields(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[
            _StubCandidate(vendor="X", model_id=None,
                           mac_oui=None, hostname=None,
                           ssh_banner=None, open_ports=[],
                           board_name=None),
        ])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args(json_output=True))

        data = json.loads(capsys.readouterr().out)
        c = data["candidates"][0]
        assert c["model_id"] is None
        assert c["mac_oui"] is None
        assert c["board_name"] is None

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_json_pretty_printed_with_indent(
        self, _log, mock_fp, mock_match, capsys,
    ):
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[_StubCandidate()])
        mock_match.return_value = []

        cmd_fingerprint(_make_fp_args(json_output=True))

        out = capsys.readouterr().out
        # indent=2 produces newlines and indented JSON
        assert "\n" in out
        assert '  "ip":' in out

    @patch("conwrt.cmd_detect._match_models")
    @patch("conwrt.cmd_detect._active_fingerprint")
    @patch("conwrt.cmd_detect.log")
    def test_json_output_flag_default_false(
        self, _log, mock_fp, mock_match, capsys,
    ):
        """If json_output attribute is missing, getattr default is False."""
        from conwrt.cmd_detect import cmd_fingerprint
        mock_fp.return_value = _StubResult(candidates=[_StubCandidate(vendor="X")])
        mock_match.return_value = []
        # Use SimpleNamespace without json_output to test getattr default
        args = SimpleNamespace(ip="192.168.1.1", timeout=5.0)

        cmd_fingerprint(args)

        out = capsys.readouterr().out
        # Human output should appear, not JSON
        assert "Vendor: X" in out


# ===========================================================================
# cmd_auto
# ===========================================================================


class TestCmdAutoInterface:
    @patch("conwrt.cmd_detect.auto_detect_interface")
    def test_no_interface_returns_1(self, mock_iface, capsys):
        from conwrt.cmd_detect import cmd_auto
        mock_iface.return_value = None

        result = cmd_auto(_make_auto_args(interface=None))

        assert result == 1
        captured = capsys.readouterr()
        assert "no active ethernet interface" in captured.err.lower()

    @patch("conwrt.cmd_detect.auto_detect_interface")
    def test_explicit_interface_used(self, mock_iface, capsys):
        """When args.interface is provided, auto_detect_interface fallback
        should not be required (args.interface short-circuits)."""
        from conwrt.cmd_detect import cmd_auto
        # auto_detect_interface won't matter if args.interface is set
        mock_iface.return_value = None

        # Mock the auto_detect call to avoid network I/O
        # Use sys.modules to inject a fake auto_detect module since
        # cmd_auto does a local import.
        with patch.dict(sys.modules, {"auto_detect": _make_fake_autodetect()}):
            result = cmd_auto(_make_auto_args(interface="eth0", no_menu=True))
        assert result == 1  # no routers detected in stub
        captured = capsys.readouterr()
        # Confirms execution proceeded past interface check
        assert "Auto-detecting routers on eth0" in captured.out


def _make_fake_autodetect(routers=None):
    """Build a stand-in `auto_detect` module with the two needed callables."""
    import types
    mod = types.ModuleType("auto_detect")
    mod.auto_detect = lambda iface, passive_timeout=10: routers or []
    mod.interactive_menu = lambda rs: None
    return mod


class TestCmdAutoNoRouters:
    @patch("conwrt.cmd_detect.auto_detect_interface")
    def test_no_routers_returns_1_with_helpful_msg(
        self, mock_iface, capsys,
    ):
        from conwrt.cmd_detect import cmd_auto
        mock_iface.return_value = "en0"

        with patch.dict(sys.modules, {"auto_detect": _make_fake_autodetect()}):
            result = cmd_auto(_make_auto_args())

        assert result == 1
        out = capsys.readouterr().out
        assert "No routers detected" in out
        assert "Ethernet cable" in out
        assert "powered on" in out
        assert "Interface is correct" in out


class TestCmdAutoNoMenu:
    @patch("conwrt.cmd_detect.auto_detect_interface")
    def test_no_menu_prints_routers_and_returns_0(
        self, mock_iface, capsys,
    ):
        from conwrt.cmd_detect import cmd_auto
        mock_iface.return_value = "en0"

        routers = [
            _StubRouter(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff",
                        vendor="D-Link", model_name="COVR-X1860",
                        firmware_state="openwrt", confidence="high"),
            _StubRouter(ip="192.168.1.2", mac="00:11:22:33:44:55",
                        vendor="GL.iNet", model_name="",
                        firmware_state="uboot", confidence="medium"),
        ]
        with patch.dict(sys.modules,
                        {"auto_detect": _make_fake_autodetect(routers)}):
            result = cmd_auto(_make_auto_args(no_menu=True))

        assert result == 0
        out = capsys.readouterr().out
        assert "192.168.1.1" in out
        assert "aa:bb:cc:dd:ee:ff" in out
        assert "D-Link" in out
        assert "COVR-X1860" in out
        assert "openwrt" in out
        assert "high" in out
        assert "192.168.1.2" in out
        # Empty model_name renders as "?"
        assert "Model: ?" in out

    @patch("conwrt.cmd_detect.auto_detect_interface")
    def test_no_menu_does_not_show_menu(
        self, mock_iface, capsys,
    ):
        """no_menu=True must NOT call interactive_menu."""
        from conwrt.cmd_detect import cmd_auto
        mock_iface.return_value = "en0"

        menu_calls = []
        fake = _make_fake_autodetect([_StubRouter()])
        fake.interactive_menu = lambda rs: menu_calls.append(rs)

        with patch.dict(sys.modules, {"auto_detect": fake}):
            cmd_auto(_make_auto_args(no_menu=True))

        assert menu_calls == []


class TestCmdAutoInteractive:
    @patch("conwrt.cmd_detect.auto_detect_interface")
    def test_interactive_menu_invoked_when_no_menu_false(
        self, mock_iface,
    ):
        from conwrt.cmd_detect import cmd_auto
        mock_iface.return_value = "en0"

        routers = [_StubRouter(), _StubRouter(ip="192.168.1.2")]
        menu_calls = []
        fake = _make_fake_autodetect(routers)
        fake.interactive_menu = lambda rs: menu_calls.append(rs)

        with patch.dict(sys.modules, {"auto_detect": fake}):
            result = cmd_auto(_make_auto_args(no_menu=False))

        assert result == 0
        # The menu was called once with the full router list
        assert len(menu_calls) == 1
        assert menu_calls[0] is routers

    @patch("conwrt.cmd_detect.auto_detect_interface")
    def test_passive_timeout_passed_to_auto_detect(
        self, mock_iface,
    ):
        from conwrt.cmd_detect import cmd_auto
        mock_iface.return_value = "en0"

        captured_args: dict = {}
        fake = _make_fake_autodetect()

        def fake_auto_detect(iface, passive_timeout=10):
            captured_args["iface"] = iface
            captured_args["timeout"] = passive_timeout
            return []

        fake.auto_detect = fake_auto_detect

        with patch.dict(sys.modules, {"auto_detect": fake}):
            cmd_auto(_make_auto_args(passive_timeout=25))

        assert captured_args["iface"] == "en0"
        assert captured_args["timeout"] == 25

    @patch("conwrt.cmd_detect.auto_detect_interface")
    def test_auto_detect_interface_called_when_no_explicit(
        self, mock_iface,
    ):
        from conwrt.cmd_detect import cmd_auto
        mock_iface.return_value = "en5"

        captured: dict = {}
        fake = _make_fake_autodetect()

        def fake_auto_detect(iface, passive_timeout=10):
            captured["iface"] = iface
            return []

        fake.auto_detect = fake_auto_detect

        with patch.dict(sys.modules, {"auto_detect": fake}):
            cmd_auto(_make_auto_args(interface=None))

        assert captured["iface"] == "en5"

    @patch("conwrt.cmd_detect.auto_detect_interface")
    def test_explicit_interface_wins_over_autodetect(
        self, mock_iface,
    ):
        from conwrt.cmd_detect import cmd_auto
        mock_iface.return_value = "en9"  # different from explicit

        captured: dict = {}
        fake = _make_fake_autodetect()

        def fake_auto_detect(iface, passive_timeout=10):
            captured["iface"] = iface
            return []

        fake.auto_detect = fake_auto_detect

        with patch.dict(sys.modules, {"auto_detect": fake}):
            cmd_auto(_make_auto_args(interface="eth1"))

        assert captured["iface"] == "eth1"
