"""Pure-logic tests for the ZTE IKE responder + overlay roulette (#763 P3).

zte_ike_responder: the ISAKMP struct shapes and the vendor-0xF3 mirror
response — payload/header framing, payload-chain walking, NAT-D hash
construction, and the F3 body ordering (the exact chain the ZAS
updater expects). No sockets.

overlay_roulette: classify()/vm_run()/record() and the persist-check
experiment driver against a fake VM class (boot/run/cut recorded) —
no QEMU, RESULTS redirected to tmp.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import zte_ike_responder as ike  # noqa: E402
import overlay_roulette as rl  # noqa: E402


def _sess(**kw):
    base = dict(icki=b"I" * 8, ickr=b"R" * 8, ke=b"K" * 64,
                nonce=b"N" * 16, peer=("10.0.0.5", 4500))
    base.update(kw)
    return SimpleNamespace(**base)


class TestIsakmpFraming:
    def test_payload_header_shape(self):
        p = ike.payload(0x01, b"\x00" * 4)
        assert p == struct.pack("!BBH", 0x01, 0, 8) + b"\x00" * 4
        h = ike.header(b"I" * 8, b"R" * 8, 0x85, 0xF3, 0x00, 7, b"BODY")
        assert len(h) == 28 + 4
        assert h[:8] == b"I" * 8 and h[8:16] == b"R" * 8
        assert h[16] == 0x85 and h[18] == 0xF3 and h[19] == 0x00
        assert struct.unpack("!II", h[20:28]) == (7, 32)

    def test_parse_payloads_walks_the_chain(self):
        # payload chain: each payload's next-type field names the TYPE of
        # the payload that follows; the header np names the FIRST type
        body = (ike.payload(0x0D, b"A" * 4)   # type 0x02 (from header np)
                + ike.payload(0x00, b"B" * 8))  # type 0x0D (prev nxt)
        data = ike.header(b"I" * 8, b"R" * 8, 0x02, 0x02, 0, 0, body)
        ps = list(ike.parse_payloads(data))
        assert [t for t, *_ in ps] == [0x02, 0x0D]
        assert ps[0][5] == b"A" * 4 and ps[1][5] == b"B" * 8

    def test_parse_payloads_stops_on_bad_length(self):
        body = b"\x00\x00\x00\x02" + b"X"  # plen 2 < 4
        data = ike.header(b"I" * 8, b"R" * 8, 0x01, 0x02, 0, 0, body)
        assert list(ike.parse_payloads(data)) == []

    def test_nat_d_hash_order(self):
        h = ike.nat_d(b"I", b"R", "10.0.0.5", 4500)
        # SHA1 over icki || ickr || ip || port — deterministic + ordered
        import hashlib
        import socket as sk
        want = hashlib.sha1(
            b"I" + b"R" + sk.inet_aton("10.0.0.5") + struct.pack("!H", 4500)
        ).digest()
        assert h == want


class TestF3Response:
    def _req(self, sa_body=b"SA", vids=(ike.VID_RFC3947,)):
        vidps = b"".join(
            ike.payload(0x0D, v) for v in vids[:-1])
        if vids:
            vidps += ike.payload(0x0D, vids[-1])
        body = (ike.payload(0x01, b"\x00\x00\x00\x00")
                + ike.payload(0x02, sa_body)
                + vidps)
        return ike.header(b"I" * 8, b"R" * 8, 0x85, 0xF3, 0x00, 0, body)

    def test_chain_order_and_echoes(self):
        sess = _sess()
        resp = ike.build_f3_response(sess, self._req(), "192.168.82.3", 500)
        assert resp[16:17] == b"\x85" and resp[18] == 0xF3
        ps = list(ike.parse_payloads(resp))
        types = [t for t, *_ in ps]
        # SA acceptance, vendor 0x85 + 0x87, nonce, VIDs, NAT-D pair, KE
        assert 0x85 in types and 1 in types and 0x87 in types
        assert types[-1] == 0x04  # KE last
        sa = next(b for t, *_z, b in [(t, b) for t, _h, _o, _p, _n, b in ps] if t == 1)
        assert sa == b"SA"  # echoed acceptance

    def test_nat_d_pair_uses_both_ends(self):
        sess = _sess(peer=("10.0.0.5", 4500))
        resp = ike.build_f3_response(sess, self._req(), "192.168.82.3", 500)
        ps = list(ike.parse_payloads(resp))
        natds = [b for t, *_z, b in [(t, b) for t, _h, _o, _p, _n, b in ps]
                 if t == 0x14]
        assert len(natds) == 2
        peer_hash = ike.nat_d(sess.icki, sess.ickr, "10.0.0.5", 4500)
        me_hash = ike.nat_d(sess.icki, sess.ickr, "192.168.82.3", 500)
        # initiator's hash first (their ip), then ours — as the client sent
        assert natds[0] == peer_hash and natds[1] == me_hash

    def test_no_vid_falls_back_to_rfc3947(self):
        sess = _sess()
        resp = ike.build_f3_response(sess, self._req(vids=()), "1.2.3.4", 500)
        ps = list(ike.parse_payloads(resp))
        vids = [b for t, *_z, b in [(t, b) for t, _h, _o, _p, _n, b in ps]
                if t == 13]
        assert vids == [ike.VID_RFC3947]


class TestMainModeResponses:
    def test_sa_echo(self):
        sess = _sess()
        body = ike.payload(0x00, b"TRANSFORMS")
        req = ike.header(b"I" * 8, b"R" * 8, 0x01, 0x02, 0, 0, body)
        resp = ike.build_mainmode_sa_response(sess, req)
        ps = list(ike.parse_payloads(resp))
        assert ps[0][5] == b"TRANSFORMS"

    def test_sa_missing_returns_none(self):
        body = ike.payload(0x00, b"NOT-SA")
        req = ike.header(b"I" * 8, b"R" * 8, 0x0D, 0x02, 0, 0, body)
        assert ike.build_mainmode_sa_response(_sess(), req) is None

    def test_mm2_ke_and_nonce(self):
        sess = _sess(ke=b"K" * 64, nonce=b"N" * 16)
        resp = ike.build_mm2_response(sess, b"")
        ps = list(ike.parse_payloads(resp))
        assert ps[0][5] == b"K" * 64
        assert ps[1][5] == b"N" * 16


# --- overlay_roulette -------------------------------------------------------

class FakeVM:
    instances: list["FakeVM"] = []
    scripted_boot = True
    scripted_runs: dict[str, str] = {}

    def __init__(self, image=None):
        self.proc = None  # the real VM starts the process in boot()
        self.cut_called = False
        self.runs = []
        FakeVM.instances.append(self)

    def boot(self, shell_timeout_s=150):
        if FakeVM.scripted_boot:
            self.proc = object()  # shell present
        return FakeVM.scripted_boot

    def run(self, cmd, timeout_s=30):
        self.runs.append(cmd)
        return FakeVM.scripted_runs.get(cmd, "ok")

    def cut(self):
        self.cut_called = True
        self.proc = None


@pytest.fixture()
def roulette(tmp_path, monkeypatch):
    FakeVM.instances = []
    FakeVM.scripted_boot = True
    FakeVM.scripted_runs = {}
    monkeypatch.setattr(rl, "VM", FakeVM)
    monkeypatch.setattr(rl, "RESULTS", tmp_path / "results.jsonl")
    monkeypatch.setattr(rl.time, "sleep", lambda s: None)
    return tmp_path


class TestClassify:
    def test_managed_row(self, roulette):
        vm = FakeVM()
        assert vm.boot()  # a booted shell is what classify expects
        FakeVM.scripted_runs = {
            "mount | grep ' on /overlay ' | cut -d' ' -f1-5": "/dev/vda on /overlay ext4",
            "ls /etc/dropbear/ 2>/dev/null | grep -c key || echo 0": "2",
            "dmesg | grep -iE 'ext4-fs error|orphan|unchecked|recovery' | tail -3": "",
            "uptime | cut -d, -f1": "up 1 min",
        }
        row = rl.classify(vm, 42.5)
        assert row["outcome"] == "managed"
        assert row["boot_seconds"] == 42.5
        assert row["overlay"] == "/dev/vda on /overlay ext4"
        assert row["dropbear_keys"] == "2"

    def test_no_shell_row(self, roulette):
        assert rl.classify(None, 1.0)["outcome"] == "no-shell"
        vm = FakeVM(); vm.proc = None
        assert rl.classify(vm, 1.0)["outcome"] == "no-shell"

    def test_vm_run_error_is_named_not_raised(self, roulette):
        class Boom:
            def run(self, cmd, timeout_s=30):
                raise RuntimeError("shell died")
        assert rl.vm_run(Boom(), "cmd") == "<err RuntimeError>"


class TestRecord:
    def test_appends_jsonl(self, roulette, tmp_path, capsys):
        rl.record({"exp": "x", "outcome": "managed"})
        rl.record({"exp": "x", "outcome": "no-shell"})
        lines = (tmp_path / "results.jsonl").read_text().splitlines()
        assert [json.loads(l)["outcome"] for l in lines] == ["managed", "no-shell"]


class TestPersistCheck:
    def test_marker_survives_rc0(self, roulette, tmp_path):
        FakeVM.scripted_runs = {"cat /overlay/CUTMARK 2>&1": "cut-marker"}
        rc = rl.cmd_persist_check(None)
        assert rc == 0
        row = json.loads((tmp_path / "results.jsonl").read_text().splitlines()[0])
        assert row["exp"] == "persist-check"
        assert row["persisted"] is True
        # every VM that BOOTED was cut (no leaked qemu); the duplicated
        # first VM() in cmd_persist_check never starts a process
        booted = [vm for vm in FakeVM.instances if vm.runs or vm.cut_called]
        assert booted and all(vm.cut_called for vm in booted)

    def test_marker_lost_rc1(self, roulette, tmp_path):
        FakeVM.scripted_runs = {"cat /overlay/CUTMARK 2>&1": "cat: not found"}
        rc = rl.cmd_persist_check(None)
        assert rc == 1
        row = json.loads((tmp_path / "results.jsonl").read_text().splitlines()[0])
        assert row["persisted"] is False

    def test_boot1_failure_records_and_rc1(self, roulette, tmp_path):
        FakeVM.scripted_boot = False
        rc = rl.cmd_persist_check(None)
        assert rc == 1
        row = json.loads((tmp_path / "results.jsonl").read_text().splitlines()[0])
        assert row["phase"] == "boot1" and row["outcome"] == "no-shell"

    def test_boot2_failure_records_no_shell(self, roulette, tmp_path):
        boots = iter([True, False])

        class TwoFace(FakeVM):
            def boot(self, shell_timeout_s=150):
                return next(boots)
        import types
        rl.VM = TwoFace
        try:
            rc = rl.cmd_persist_check(None)
        finally:
            rl.VM = FakeVM
        assert rc == 1
        row = json.loads((tmp_path / "results.jsonl").read_text().splitlines()[0])
        assert row["phase"] == "boot2" and row["outcome"] == "no-shell"
