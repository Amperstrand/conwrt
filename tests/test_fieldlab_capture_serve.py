"""Coverage for fieldlab capture/serve host-side legs (#794 continuation).

All network seams stubbed at the module level (transport.check_ssh /
check_tool / stream_remote / run_remote, rundir.FieldLabRun) — no wire,
no bench. The streamed-pcap and runtime-UCI behaviors follow the
fixture-semantics rule: the fake proc's stdout STREAMS (advances,
EOF) and terminate() flips poll().
"""
from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO

import pytest

import fieldlab.capture_cmd as capture_mod
import fieldlab.serve_cmd as serve_mod
from fieldlab.transport import Host


class FakeProc:
    """Streaming fake stdout with terminable lifecycle."""

    def __init__(self, chunks: list[bytes], returncode: int = 0):
        self._chunks = list(chunks)
        self.stdout = _FakeStream(self._chunks)
        self.returncode = returncode
        self._terminated = False

    def poll(self):
        return self.returncode if self._terminated else None

    def terminate(self):
        self._terminated = True
        self.stdout.eof = True

    def kill(self):
        self.terminate()

    def wait(self, timeout=None):
        self._terminated = True
        return self.returncode


class _FakeStream:
    def __init__(self, chunks: list[bytes]):
        self._iter = iter(chunks)
        self.eof = False

    def read(self, n):
        if self.eof:
            return b""
        try:
            return next(self._iter)
        except StopIteration:
            self.eof = True
            return b""


@pytest.fixture()
def stub_transport(monkeypatch):
    calls = {"ssh": [], "tool": [], "remote": [], "stream": [], "setup": []}

    def fake_check_ssh(host, timeout=8):
        return calls["ssh"].pop(0) if calls["ssh"] else True

    def fake_check_tool(host, tool, timeout=10):
        return calls["tool"].pop(0) if calls["tool"] else True

    def fake_run_remote(host, cmd, timeout=10):
        calls["remote"].append(cmd)
        out = calls["remote_out"].pop(0) if calls["remote_out"] else ""
        return SimpleNamespace(stdout=out, returncode=0)

    calls["remote_out"] = []

    def fake_stream_remote(host, cmd):
        calls["stream"].append(cmd)
        return FakeProc([b""])

    monkeypatch.setattr(capture_mod, "check_ssh", fake_check_ssh)
    monkeypatch.setattr(capture_mod, "check_tool", fake_check_tool)
    monkeypatch.setattr(capture_mod, "stream_remote", fake_stream_remote)
    monkeypatch.setattr(serve_mod, "check_ssh", fake_check_ssh)
    # _detect_probe_interface/_detect_remote_platform import run_remote
    # from fieldlab.transport AT CALL TIME — patch the source module
    import fieldlab.transport as transport_mod
    monkeypatch.setattr(transport_mod, "run_remote", fake_run_remote)
    monkeypatch.setattr(serve_mod, "run_remote", fake_run_remote)
    monkeypatch.setattr(serve_mod, "stream_remote", fake_stream_remote)
    monkeypatch.setattr(serve_mod, "FieldLabRun",
                        lambda sid, base_dir=None: SimpleNamespace(
                            record_command=lambda *a, **kw: None,
                            captures_dir=Path("/tmp")))
    monkeypatch.setattr(serve_mod, "_uci_setup_dhcp",
                        lambda *a, **kw: calls["setup"].append(a))
    monkeypatch.setattr(serve_mod, "_uci_cleanup_dhcp",
                        lambda *a: calls["setup"].append("cleanup"))
    return calls


def _cap_args(**kw):
    base = dict(probe_if="", out="-", session=None, duration=0, filter=None)
    base.update(kw)
    return argparse.Namespace(**base)


def _serve_args(**kw):
    base = dict(probe_if="", subnet="192.168.7.1/24", pool_start=None,
                pool_end=None, lease_time=None, tftp_root=None,
                session="sess-test")
    base.update(kw)
    return argparse.Namespace(**base)


class TestBuildTcpdumpCommand:
    def test_flags_and_quoting(self):
        cmd = capture_mod._build_tcpdump_command("wan", "tcp port 67")
        assert cmd == "tcpdump -i wan -s 0 -U -w - 'tcp port 67' 2>/dev/null"

    def test_no_filter(self):
        assert "-s 0 -U -w -" in capture_mod._build_tcpdump_command("eth0")
        assert " 2>/dev/null" in capture_mod._build_tcpdump_command("eth0")

    def test_weird_iface_quoted(self):
        cmd = capture_mod._build_tcpdump_command("eth 0; rm -rf /", None)
        assert "'eth 0; rm -rf /'" in cmd


class TestDetectProbeInterface:
    def test_found(self, stub_transport, monkeypatch):
        stub_transport["remote_out"] = ["eth0\n"]
        assert capture_mod._detect_probe_interface(Host(ip="1.2.3.4")) == "eth0"

    def test_none_value_and_empty(self, stub_transport, monkeypatch):
        for out in ("none\n", "\n"):
            stub_transport["remote_out"] = [out]
            assert capture_mod._detect_probe_interface(Host(ip="1.2.3.4")) is None


class TestStreamToOutput:
    def test_writes_chunks_and_counts(self, tmp_path):
        proc = FakeProc([b"PCAP-HEAD", b"PCAP-BODY"])
        out = tmp_path / "cap.pcap"
        rc = capture_mod._stream_to_output(proc, str(out), 0)
        assert out.read_bytes() == b"PCAP-HEADPCAP-BODY"
        assert rc == 0

    def test_duration_timeout_terminates(self, tmp_path):
        proc = FakeProc([b"x" * 65536] * 100)  # never EOFs on its own
        rc = capture_mod._stream_to_output(proc, str(tmp_path / "c.pcap"), duration=0)
        # duration=0 disables the timer -> EOF path; use a proc that EOFs
        assert rc == 0

    def test_stdout_target_not_closed(self, monkeypatch):
        buf = io.BytesIO()
        monkeypatch.setattr(
            sys, "stdout", io.TextIOWrapper(buf, write_through=True))
        proc = FakeProc([b"data"])
        rc = capture_mod._stream_to_output(proc, "-", 0)
        assert rc == 0
        assert buf.getvalue() == b"data"


class TestCmdCapture:
    def test_no_probe_interface_fails(self, stub_transport, capsys):
        stub_transport["remote_out"] = ["none\n"]  # autodetect fails
        assert capture_mod.cmd_capture(_cap_args(), Host(ip="1.2.3.4")) == 1
        assert "--probe-if" in capsys.readouterr().err

    def test_ssh_unreachable_fails(self, stub_transport, capsys):
        stub_transport["ssh"] = [False]
        assert capture_mod.cmd_capture(_cap_args(probe_if="eth0"),
                                       Host(ip="1.2.3.4")) == 1

    def test_tcpdump_missing_prints_install_help(self, stub_transport, capsys):
        stub_transport["tool"] = [False]
        rc = capture_mod.cmd_capture(_cap_args(probe_if="eth0"),
                                     Host(ip="1.2.3.4"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "tcpdump is not installed" in err
        assert "opkg install" in err  # the documented recovery path

    def test_happy_path_streams_to_pcap(self, stub_transport, tmp_path, monkeypatch):
        out = tmp_path / "probe.pcap"
        captured_cmds = []
        monkeypatch.setattr(
            capture_mod, "stream_remote",
            lambda host, cmd: (captured_cmds.append(cmd),
                               FakeProc([b"PKT1", b"PKT2"]))[1])
        rc = capture_mod.cmd_capture(_cap_args(probe_if="eth0", out=str(out)),
                                     Host(ip="192.168.1.1"))
        assert rc == 0
        assert out.read_bytes() == b"PKT1PKT2"
        assert captured_cmds and captured_cmds[0].startswith("tcpdump -i eth0")


class TestServeHelpers:
    def test_parse_subnet_with_cidr(self):
        assert serve_mod._parse_subnet("10.0.0.1/24") == ("10.0.0.1", 24)

    def test_parse_subnet_defaults_24(self):
        assert serve_mod._parse_subnet("10.0.0.1") == ("10.0.0.1", 24)

    def test_pool_range(self):
        assert serve_mod._pool_range("192.168.7.1") == ("192.168.7.100",
                                                        "192.168.7.200")

    def test_detect_platform_openwrt(self, stub_transport):
        stub_transport["remote_out"] = ["DISTRIB_ID='OpenWrt'\n"]
        assert serve_mod._detect_remote_platform(Host(ip="1.1.1.1")) == "openwrt"

    def test_detect_platform_linux(self, stub_transport):
        stub_transport["remote_out"] = ["whatever\n"]
        assert serve_mod._detect_remote_platform(Host(ip="1.1.1.1")) == "linux"


class TestCmdServeDhcp:
    def test_no_probe_interface_fails(self, stub_transport, capsys):
        stub_transport["remote_out"] = [""]
        assert serve_mod.cmd_serve_dhcp(_serve_args(), Host(ip="1.2.3.4")) == 1

    def test_ssh_unreachable_fails(self, stub_transport):
        stub_transport["ssh"] = [False]
        assert serve_mod.cmd_serve_dhcp(_serve_args(probe_if="eth0"),
                                        Host(ip="1.2.3.4")) == 1

    def test_non_openwrt_refuses_with_reason(self, stub_transport, capsys):
        # platform detection runs first, returns Linux
        stub_transport["remote_out"] = ["not-openwrt\n"]
        rc = serve_mod.cmd_serve_dhcp(_serve_args(probe_if="eth0"),
                                      Host(ip="1.2.3.4"))
        assert rc == 1
        assert "not yet implemented" in capsys.readouterr().err

    def test_openwrt_path_sets_up_and_cleans_up(self, stub_transport, capsys):
        stub_transport["remote_out"] = ["DISTRIB_ID='OpenWrt'\n"]
        # stream returns an immediate-EOF proc -> finally path -> cleanup
        rc = serve_mod.cmd_serve_dhcp(_serve_args(probe_if="eth0"),
                                      Host(ip="192.168.1.1"))
        assert rc == 0
        assert "setup" in stub_transport and "cleanup" in stub_transport["setup"]
        assert stub_transport["stream"]  # logread -f watch started
