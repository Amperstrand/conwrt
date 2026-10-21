"""bench_adopt — assertion tests (hardware-safe; canned transports only).

Canned outputs below are REAL captures from the 2026-09-22 ap-lan4 spike,
so the assertions are pinned against ground truth, not fiction.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import bench_adopt as ba

PLACE = ba.Place("ap-lan4", "b4:2d:56:25:79:b1", "192.168.104.51")

# A valid receipt for PLACE — stage_reset must see one of these (fail-closed).
RECEIPT = ba.EnvelopeReceipt(
    place="ap-lan4", vlan=1004, tftproot="/tmp/bench-tftp",
    lifeline_log="/tmp/tftp-1004.log",
    recorder_log="/tmp/bench-aliveness-ap-lan4.log")

# Real captures from the spike (verbatim, trimmed to what matters).
PREFLIGHT_OK = """extreme-networks,ws-ap3915i
DISTRIB_RELEASE='24.10.2'
 20:46:34 up 4 min,  load average: 0.00, 0.07, 0.04
    inet6 fe80::b62d:56ff:fe25:79b1/64 scope global br-lan"""

RESET_FACTORY = """ 20:46:34 up 2 min,  load average: 0.00, 0.07, 0.04
ls: /etc/dropbear/authorized_keys: No such file or directory
ls: /root/.ssh/authorized_keys: No such file or directory
DISTRIB_RELEASE='24.10.2'
extreme-networks,ws-ap3915i"""

RESET_NOT_WIPED = """ 20:46:34 up 2 min,  load average: 0.00, 0.07, 0.04
3 /etc/dropbear/authorized_keys
DISTRIB_RELEASE='24.10.2'
extreme-networks,ws-ap3915i"""

ADOPT_PENDING_REAL = """---PENDING---
network.lan.proto='static'
-network.lan.ipaddr
network.lan.ipaddr+='192.168.104.51/24'
network.lan.gateway='192.168.104.1'
network.lan.dns='192.168.104.1'"""

VERIFY_OK = """SSH-OK-NEW-IP
static
    inet 192.168.104.51/24 brd 192.168.104.255 scope global br-lan
DISTRIB_RELEASE='24.10.2'
192.168.104.51 dev switch.1004 lladdr b4:2d:56:25:79:b1 ref 1 used 0/0/0 probes 1 REACHABLE"""


class TestEui64GroundTruth:
    @pytest.mark.parametrize("mac,expected", [
        ("b4:2d:56:25:79:b1", "fe80::b62d:56ff:fe25:79b1"),  # observed switch.1004
        ("b4:2d:56:25:47:a2", "fe80::b62d:56ff:fe25:47a2"),  # observed switch.1003
        ("dc:b8:08:6c:ea:7f", "fe80::deb8:8ff:fe6c:ea7f"),   # observed switch.1002
        ("b4:2d:56:24:ad:97", "fe80::b62d:56ff:fe24:ad97"),  # observed switch.1005
    ])
    def test_live_observed_pairs(self, mac: str, expected: str) -> None:
        assert ba.eui64_linklocal(mac) == expected

    def test_bit_flip_and_canonical_form(self) -> None:
        assert ba.eui64_linklocal("02:aa:bb:cc:dd:ee") == "fe80::aa:bbff:fecc:ddee"

    def test_bad_mac_rejected(self) -> None:
        with pytest.raises(ba.AdoptError, match="bad MAC"):
            ba.eui64_linklocal("not-a-mac")


class TestPlaceDerivation:
    def test_vlan_mnemonic(self) -> None:
        assert PLACE.vlan == 1004
        assert ba.Place("ap-lan7", "m", "i").vlan == 1007

    def test_linklocal_property(self) -> None:
        assert PLACE.linklocal == "fe80::b62d:56ff:fe25:79b1"


SWITCH_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJb4PBnGmVcWqX0OZ8pT"
              "+3QMq7dH2iWc1Rk0vKqZf1kQ root@switch")


class TestAdoptFullFlow:
    @pytest.fixture(autouse=True)
    def _no_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ba.time, "sleep", lambda s: None)
        monkeypatch.setattr(ba.time, "monotonic", lambda: 0)

    def test_value_readback_flow_passes(self, tmp_path: Path) -> None:
        canned = [
            "extreme-networks,ws-ap3915i",                          # adopt-ready
            SWITCH_KEY,                                            # adopt-switchkey
            "KEYS-PUSHED\nKEY-AUTH-OK\n3 /etc/dropbear/authorized_keys",  # adopt-keys
            "---READBACK---\nstatic\n192.168.104.51/24\n192.168.104.1\n192.168.104.1",
            "COMMITTED\nRESTARTED",
        ]
        ba.stage_adopt(_runner(canned, tmp_path))

    def test_wrong_readback_value_refuses_commit(self, tmp_path: Path) -> None:
        canned = [
            "extreme-networks,ws-ap3915i",
            SWITCH_KEY,
            "KEYS-PUSHED\nKEY-AUTH-OK\n3 /etc/dropbear/authorized_keys",
            "---READBACK---\nstatic\n192.168.1.1/24\n192.168.104.1\n192.168.104.1",
        ]
        with pytest.raises(ba.AdoptError, match="readback mismatch"):
            ba.stage_adopt(_runner(canned, tmp_path))

    def test_staging_reverts_stale_pending_first(self, tmp_path: Path) -> None:
        scripts: list[str] = []
        canned = iter([
            "extreme-networks,ws-ap3915i",
            SWITCH_KEY,
            "KEYS-PUSHED\nKEY-AUTH-OK\n3",
            "---READBACK---\nstatic\n192.168.104.51/24\n192.168.104.1\n192.168.104.1",
            "COMMITTED",
        ])

        def capture(script: str) -> str:
            scripts.append(script)
            return next(canned)

        ba.stage_adopt(ba.Runner(capture, PLACE, tmp_path / "ev"))
        assert any("uci revert network" in s for s in scripts), \
            "staging must start from a clean baseline"


def _runner(canned: str | list[str], tmp_path: Path, place: ba.Place = PLACE) -> ba.Runner:
    remaining = list(canned) if isinstance(canned, list) else None

    def serve(_script: str) -> str:
        if remaining is not None:
            if not remaining:
                raise AssertionError("canned transport exhausted")
            return remaining.pop(0)
        return canned  # type: ignore[return-value]

    return ba.Runner(serve, place, tmp_path / "ev")


class TestPreflightAssertions:
    def test_real_capture_passes(self, tmp_path: Path) -> None:
        ba.stage_preflight(_runner(PREFLIGHT_OK, tmp_path))

    def test_wrong_board_fails(self, tmp_path: Path) -> None:
        bad = PREFLIGHT_OK.replace("extreme-networks", "other-vendor")
        with pytest.raises(ba.AdoptError, match="board mismatch"):
            ba.stage_preflight(_runner(bad, tmp_path))

    def test_wrong_release_fails(self, tmp_path: Path) -> None:
        bad = PREFLIGHT_OK.replace("24.10.2", "25.12.5")
        with pytest.raises(ba.AdoptError, match="release mismatch"):
            ba.stage_preflight(_runner(bad, tmp_path))

    def test_missing_v6_channel_fails(self, tmp_path: Path) -> None:
        bad = "\n".join(l for l in PREFLIGHT_OK.splitlines() if "fe80" not in l)
        with pytest.raises(ba.AdoptError, match="v6 channel"):
            ba.stage_preflight(_runner(bad, tmp_path))

    def test_per_place_release_expectation(self, tmp_path: Path) -> None:
        unit2 = ba.Place("ap-lan2", "dc:b8:08:6c:ea:7f", "192.168.102.51",
                         release="25.12.5")
        ba.stage_preflight(_runner(PREFLIGHT_OK.replace("24.10.2", "25.12.5"),
                                   tmp_path, place=unit2))


ROM_AUDIT_OK = """root:::0:99999:7:::
	option PasswordAuth 'on'
	option RootPasswordAuth 'on'"""

ROM_AUDIT_LOCKED = """root:!:0:99999:7:::
	option PasswordAuth 'on'
	option RootPasswordAuth 'on'"""

ROM_AUDIT_NO_PASSAUTH = """root:::0:99999:7:::
	option PasswordAuth 'off'
	option RootPasswordAuth 'on'"""


class TestRomAudit:
    def test_blank_root_and_passauth_passes(self, tmp_path: Path) -> None:
        ba.stage_rom_audit(_runner(ROM_AUDIT_OK, tmp_path))

    def test_locked_root_refuses_reset(self, tmp_path: Path) -> None:
        with pytest.raises(ba.AdoptError, match="ZERO auth methods"):
            ba.stage_rom_audit(_runner(ROM_AUDIT_LOCKED, tmp_path))

    def test_passauth_off_refuses_reset(self, tmp_path: Path) -> None:
        with pytest.raises(ba.AdoptError, match="refuses password auth"):
            ba.stage_rom_audit(_runner(ROM_AUDIT_NO_PASSAUTH, tmp_path))


class TestResetPostconditions:
    ARM = ["FIRSTBOOT-RC=0", "FIRSTBOOT-RC=0", ""]

    def _no_sleep(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ba.time, "sleep", lambda s: None)
        # 10s ticks: the persistent-auth-death ladder needs 12 poll
        # iterations inside stage_reset's 240s deadline (4 auth-dead polls
        # per round, 2 PoE-heal rounds, then the final verdict round).
        ticks = iter(list(range(0, 240, 10)) + [999])
        monkeypatch.setattr(ba.time, "monotonic", lambda: next(ticks))

    def test_keys_surviving_means_not_wiped(self, tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
        self._no_sleep(monkeypatch)
        with pytest.raises(ba.AdoptError, match="overlay was NOT wiped"):
            ba.stage_reset(_runner(self.ARM + [RESET_NOT_WIPED], tmp_path),
                           envelope=RECEIPT)

    def test_nonzero_firstboot_rc_fails_fast(self, tmp_path: Path) -> None:
        with pytest.raises(ba.AdoptError, match="nonzero"):
            ba.stage_reset(_runner(["FIRSTBOOT-RC=1", "FIRSTBOOT-RC=1"], tmp_path),
                           envelope=RECEIPT)

    def test_factory_state_passes(self, tmp_path: Path,
                                  monkeypatch: pytest.MonkeyPatch) -> None:
        self._no_sleep(monkeypatch)
        ba.stage_reset(_runner(self.ARM + [RESET_FACTORY], tmp_path),
                       envelope=RECEIPT)

    def test_mid_reboot_noise_then_factory(self, tmp_path: Path,
                                           monkeypatch: pytest.MonkeyPatch) -> None:
        self._no_sleep(monkeypatch)
        noise = ("dbclient: Connection to root@fe80::...%switch.1003:22 exited: "
                 "Remote closed the connection\n")
        ba.stage_reset(_runner(self.ARM + [noise, noise, RESET_FACTORY], tmp_path),
                       envelope=RECEIPT)

    def test_persistent_auth_death_fails_fast(self, tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
        # Regression note (#141): master's reset postcondition loop (via the
        # #67 merge) no longer fails fast on auth death — it runs the bounded
        # jffs2-replay cure first (<=2 deliberate PoE cycles, AGENTS.md
        # reset-failsafe rule 5) and only then verdicts CONSOLE REQUIRED.
        self._no_sleep(monkeypatch)
        noise = ("dbclient: Connection to root@fe80::...%switch.1002:22 exited: "
                 "Remote closed the connection\n")
        poe_ack = ['{"status":"okay"}\n']
        canned = self.ARM + ([noise] * 4 + poe_ack        # round 1 -> HEAL 1/2
                             + [noise] * 4 + poe_ack      # round 2 -> HEAL 2/2
                             + [noise] * 4)               # round 3 -> verdict
        with pytest.raises(ba.AdoptError, match="CONSOLE REQUIRED"):
            ba.stage_reset(_runner(canned, tmp_path), envelope=RECEIPT)

    def test_auth_death_healed_by_poecycle_passes(self, tmp_path: Path,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
        # One deliberate PoE cycle re-runs the jffs2 replay and the unit
        # comes back factory-clean (ap-lan2 + ap-lan5 pattern) — adoption
        # proceeds instead of verdicting console-required.
        self._no_sleep(monkeypatch)
        noise = ("dbclient: Connection to root@fe80::...%switch.1002:22 exited: "
                 "Remote closed the connection\n")
        canned = self.ARM + [noise] * 4 + ['{"status":"okay"}\n'] + [RESET_FACTORY]
        ba.stage_reset(_runner(canned, tmp_path), envelope=RECEIPT)

    def test_reset_refused_for_tftp_dependent_unit(self, tmp_path: Path) -> None:
        lan5 = ba.Place("ap-lan5", "b4:2d:56:24:ad:97", "192.168.105.51",
                        reset_allowed=False)
        with pytest.raises(ba.AdoptError, match="refused"):
            ba.stage_reset(_runner("", tmp_path, place=lan5))


class TestAdoptReadiness:
    def test_auth_dead_factory_fails_before_keys(self, tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ba.time, "sleep", lambda s: None)
        monkeypatch.setattr(ba.time, "monotonic", lambda: 0)
        noise = "dbclient: Remote closed the connection\n"
        with pytest.raises(ba.AdoptError, match="refuses all sessions"):
            ba.stage_adopt(_runner(noise, tmp_path))

    def test_never_ready_times_out(self, tmp_path: Path,
                                   monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ba.time, "sleep", lambda s: None)
        ticks = iter([0, 30, 60, 90, 120, 999])
        monkeypatch.setattr(ba.time, "monotonic", lambda: next(ticks))
        with pytest.raises(ba.AdoptError, match="never became shell-ready"):
            ba.stage_adopt(_runner("not-a-board\n", tmp_path))


class TestVerifyAssertions:
    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ba.time, "sleep", lambda s: None)

    def test_real_capture_passes(self, tmp_path: Path) -> None:
        ba.stage_verify(_runner(VERIFY_OK, tmp_path))

    def test_ssh_failure_is_fatal(self, tmp_path: Path) -> None:
        with pytest.raises(ba.AdoptError, match="SSH-OK-NEW-IP"):
            ba.stage_verify(_runner(VERIFY_OK.replace("SSH-OK-NEW-IP", "NEW-IP-SSH-FAIL"),
                                    tmp_path))

    def test_wrong_proto_is_fatal(self, tmp_path: Path) -> None:
        with pytest.raises(ba.AdoptError, match="static"):
            ba.stage_verify(_runner(VERIFY_OK.replace("static", "dhcp"), tmp_path))


class TestScriptInvariants:
    def test_dut_scripts_close_stdin(self, tmp_path: Path) -> None:
        scripts: list[str] = []

        def capture(script: str) -> str:
            scripts.append(script)
            return PREFLIGHT_OK

        ba.stage_preflight(ba.Runner(capture, PLACE, tmp_path / "ev"))
        assert scripts, "no script generated"
        for script in scripts:
            assert "</dev/null" in script, "dbclient must not eat the piped script"
            assert "timeout " not in script, "BusyBox here has no timeout applet"


class TestCliGate:
    def test_mutation_refused_without_i_know(self, tmp_path: Path,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
        reg = tmp_path / "places.json"
        reg.write_text('{"places": [{"name": "ap-x", "mac": "02:aa:bb:cc:dd:ee", '
                       '"dut_ip": "192.168.109.51"}]}')
        rc = ba.main(["--place", "ap-x", "--places", str(reg),
                      "--stages", "reset"])
        assert rc == 2

    def test_unknown_place_rejected(self, tmp_path: Path) -> None:
        reg = tmp_path / "places.json"
        reg.write_text('{"places": []}')
        assert ba.main(["--place", "ghost", "--places", str(reg)]) == 2


class TestKeyAuthProof:
    def test_key_proof_poisons_password_fallback(self, tmp_path: Path) -> None:
        # dbclient silently falls back pubkey -> password auth; the -i proof
        # must set a bogus password so KEY-AUTH-OK can only mean pubkey.
        scripts: list[str] = []
        canned = iter([
            "extreme-networks,ws-ap3915i",
            SWITCH_KEY,
            "KEYS-PUSHED\nKEY-AUTH-OK\n3",
            "---READBACK---\nstatic\n192.168.104.51/24\n192.168.104.1\n192.168.104.1",
            "COMMITTED",
        ])

        def capture(script: str) -> str:
            scripts.append(script)
            return next(canned)

        ba.stage_adopt(ba.Runner(capture, PLACE, tmp_path / "ev"))
        keys_script = next(s for s in scripts if "KEY-AUTH-OK" in s)
        proof_line = [ln for ln in keys_script.splitlines() if "-i /root/.ssh/id_ed25519" in ln][0]
        assert "DROPBEAR_PASSWORD=" in proof_line, (
            "key proof must poison password fallback (bare -i passes on the "
            "blank/known password — NR7101 2026-09-23 lesson)")


class TestOverlayKeepsKeyAuthEvidence:
    """#288: on an adopted unit key auth SUCCEEDS but `dmesg | grep
    jffs2_build_xattr` never prints the board name — the old fallback
    discarded that evidence, retried over the (failing) empty-password
    channel, and the overlay gate read the auth error as 'no debris' =>
    false PASS right before firstboot."""

    DEBRIS_KEYAUTH = ("jffs2_scan_xattr: 3 unchecked, 1 orphan\n" + ba.PROBE_DONE)
    CLEAN_KEYAUTH = ba.PROBE_DONE
    AUTH_ERROR = "dbclient: Remote closed the connection"

    @staticmethod
    def _runner_seq(outputs: list[str], tmp_path: Path, place: ba.Place = PLACE):
        calls: list[str] = []
        canned = iter(outputs)

        def transport(script: str) -> str:
            calls.append(script)
            return next(canned)

        return ba.Runner(transport, place, tmp_path / "ev"), calls

    def test_keyauth_debris_never_passes_overlay(self, tmp_path, capsys) -> None:
        # THE #288 finding: debris via key auth + failing password channel
        r, calls = self._runner_seq([self.DEBRIS_KEYAUTH, self.AUTH_ERROR], tmp_path)
        with pytest.raises(ba.AdoptError, match="DIRTY jffs2 overlay"):
            ba.stage_overlay(r)
        assert "[PASS] overlay" not in capsys.readouterr().out

    def test_keyauth_evidence_not_discarded_no_retry(self, tmp_path) -> None:
        # key-auth output bearing the marker is authoritative: no password
        # retry may even be attempted (the retry is what destroyed evidence)
        r, calls = self._runner_seq([self.DEBRIS_KEYAUTH], tmp_path)
        with pytest.raises(ba.AdoptError, match="DIRTY"):
            ba.stage_overlay(r)
        assert len(calls) == 1, "marker-bearing key-auth output must not trigger a retry"

    def test_keyauth_clean_overlay_passes(self, tmp_path, capsys) -> None:
        r, _ = self._runner_seq([self.CLEAN_KEYAUTH], tmp_path)
        ba.stage_overlay(r)
        assert "no jffs2 xattr debris" in capsys.readouterr().out

    def test_zero_counts_passes(self, tmp_path, capsys) -> None:
        r, _ = self._runner_seq(
            ["jffs2_scan_xattr: 0 unchecked, 0 orphan\n" + ba.PROBE_DONE], tmp_path)
        ba.stage_overlay(r)
        assert "clean overlay" in capsys.readouterr().out

    def test_fallback_still_used_for_never_adopted_unit(self, tmp_path, capsys) -> None:
        # factory unit: key auth errors, empty-password channel works
        r, _ = self._runner_seq(
            [self.AUTH_ERROR, "jffs2: no xattrs\n" + ba.PROBE_DONE], tmp_path)
        ba.stage_overlay(r)
        assert "no jffs2 xattr debris" in capsys.readouterr().out

    def test_both_channels_dead_refuses_instead_of_passing(self, tmp_path) -> None:
        r, _ = self._runner_seq([self.AUTH_ERROR, self.AUTH_ERROR], tmp_path)
        with pytest.raises(ba.AdoptError, match="never completed"):
            ba.stage_overlay(r)


class TestDutWithFallbackPreservesEvidence:
    def _runner(self, outputs: list[str], tmp_path: Path):
        canned = iter(outputs)
        calls: list[str] = []

        def transport(script: str) -> str:
            calls.append(script)
            return next(canned)

        return ba.Runner(transport, PLACE, tmp_path / "ev"), calls

    def test_board_bearing_output_returned_directly(self, tmp_path) -> None:
        r, calls = self._runner([PREFLIGHT_OK], tmp_path)
        out = ba.dut_with_fallback(r, "x", "cat /tmp/sysinfo/board_name")
        assert "ws-ap3915i" in out
        assert len(calls) == 1

    def test_marker_bearing_output_returned_without_retry(self, tmp_path) -> None:
        # #288 core: no board name, but the probe demonstrably ran
        r, calls = self._runner([ba.PROBE_DONE], tmp_path)
        out = ba.dut_with_fallback(r, "x", "dmesg | grep xattr; echo PROBE-DONE")
        assert ba.PROBE_DONE in out
        assert len(calls) == 1, "successful key-auth evidence must not be discarded"

    def test_dead_key_channel_falls_back(self, tmp_path) -> None:
        r, calls = self._runner(["auth error", PREFLIGHT_OK], tmp_path)
        out = ba.dut_with_fallback(r, "x", "cat /tmp/sysinfo/board_name")
        assert "ws-ap3915i" in out
        assert len(calls) == 2

    def test_both_dead_returns_combined_for_the_caller_to_judge(self, tmp_path) -> None:
        r, _ = self._runner(["key died", "pw died"], tmp_path)
        out = ba.dut_with_fallback(r, "x", "true")
        assert "key died" in out and "pw died" in out


class TestSwitchKeyInstalledSwitchSide:
    """#291: the adopt-keys payload must embed the switch pubkey (read
    SWITCH-side), never reference /root/.ssh/id_ed25519.pub DUT-side — that
    file does not exist on a factory unit, so the switch key was never
    installed and the KEY-AUTH-OK gate could only pass by other means."""

    @pytest.fixture(autouse=True)
    def _no_time(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(ba.time, "sleep", lambda s: None)
        monkeypatch.setattr(ba.time, "monotonic", lambda: 0)
        # deterministic mac_keys: none (isolates the switch-key path)
        monkeypatch.setattr(ba.Path, "home", classmethod(lambda cls: tmp_path))

    def _run_and_capture(self, tmp_path: Path) -> list[str]:
        scripts: list[str] = []
        canned = iter([
            "extreme-networks,ws-ap3915i",       # adopt-ready
            SWITCH_KEY,                          # adopt-switchkey
            "KEYS-PUSHED\nKEY-AUTH-OK\n1",       # adopt-keys
            "---READBACK---\nstatic\n192.168.104.51/24\n192.168.104.1\n192.168.104.1",
            "COMMITTED\nRESTARTED",
        ])

        def capture(script: str) -> str:
            scripts.append(script)
            return next(canned)

        ba.stage_adopt(ba.Runner(capture, PLACE, tmp_path / "ev"))
        return scripts

    def test_switch_key_fetched_switch_side_first(self, tmp_path: Path) -> None:
        scripts = self._run_and_capture(tmp_path)
        fetch = next(s for s in scripts if "cat /root/.ssh/id_ed25519.pub" in s)
        assert "dbclient" not in fetch, "key fetch must run on the switch, not via DUT"

    def test_payload_has_no_dut_side_key_read(self, tmp_path: Path) -> None:
        scripts = self._run_and_capture(tmp_path)
        keys_line = next(ln for s in scripts for ln in s.splitlines()
                         if "KEYS-PUSHED" in ln)
        assert "$(head -c 24" not in keys_line
        assert "cat /root/.ssh/id_ed25519.pub" not in keys_line, \
            "payload runs on a factory DUT where that file does not exist"
        assert SWITCH_KEY in keys_line, "switch key content must be embedded"

    def test_missing_switch_key_fails_loudly(self, tmp_path: Path) -> None:
        canned = iter([
            "extreme-networks,ws-ap3915i",
            "",  # switch-side fetch returned nothing
        ])

        def capture(script: str) -> str:
            return next(canned)

        with pytest.raises(ba.AdoptError, match="cannot read the switch pubkey"):
            ba.stage_adopt(ba.Runner(capture, PLACE, tmp_path / "ev"))

    @staticmethod
    def _payload(scripts: list[str]) -> str:
        keys_line = next(ln for s in scripts for ln in s.splitlines()
                         if "KEYS-PUSHED" in ln)
        # payload rides inside double quotes on the dbclient line
        return keys_line.split('"', 1)[1].rsplit('"', 1)[0]

    def test_factory_fresh_stub_installs_key_exactly_once(self, tmp_path: Path) -> None:
        import subprocess
        scripts = self._run_and_capture(tmp_path)
        payload = self._payload(scripts)
        # simulate the factory DUT: rewrite /etc/dropbear into the sandbox
        # (the factory unit has NO /root/.ssh — which is the whole bug)
        dut_etc = tmp_path / "factory-dut/etc/dropbear"
        payload = payload.replace("/etc/dropbear", str(dut_etc))
        for _ in range(2):  # idempotent across two runs
            subprocess.run(["/bin/sh", "-c", payload], check=True)
        installed = (dut_etc / "authorized_keys").read_text()
        assert installed.count(SWITCH_KEY) == 1, \
            "switch key must land exactly once, not duplicate across runs"


class FakeSession:
    """Transport seam for stage_envelope: only switch_put is exercised.
    switch_sh raises if actually invoked — CLI-gate tests must refuse
    before any switch traffic."""

    def __init__(self) -> None:
        self.pushed: list[tuple[str, str]] = []

    def switch_put(self, local: Path, remote: str) -> None:
        self.pushed.append((str(local), remote))

    @staticmethod
    def switch_sh(_script: str, timeout_s: int = 90) -> str:
        raise AssertionError("FakeSession.switch_sh must not be called")


def _seq_runner(outputs: list[str], tmp_path: Path, place: ba.Place = PLACE
                ) -> tuple[ba.Runner, list[str]]:
    calls: list[str] = []
    canned = iter(outputs)

    def transport(script: str) -> str:
        calls.append(script)
        return next(canned)

    return ba.Runner(transport, place, tmp_path / "ev"), calls


class TestEnvelopeStage:
    """#289: the envelope stage arms lifeline + recorder + blank-password
    proof, refuses firstboot on any unverified part, and returns the
    receipt stage_reset demands."""

    def _run(self, outputs: list[str], tmp_path: Path, image_path: Path | None = None,
             digest: str = "") -> tuple[ba.EnvelopeReceipt, list[str], FakeSession]:
        session = FakeSession()
        r, calls = _seq_runner(outputs, tmp_path)
        receipt = ba.stage_envelope(r, "/tmp/bench-tftp", "rec.bin",
                                    image_path, digest, session)
        return receipt, calls, session

    def test_full_envelope_passes_and_returns_receipt(self, tmp_path: Path) -> None:
        receipt, _, session = self._run(
            ["LIFELINE-OK", ba.RECORDER_OK,
             ba.BLANK_CHANNEL_OK + "\nextreme-networks,ws-ap3915i"], tmp_path)
        assert receipt == ba.EnvelopeReceipt(
            place="ap-lan4", vlan=1004, tftproot="/tmp/bench-tftp",
            lifeline_log="/tmp/tftp-1004.log",
            recorder_log="/tmp/bench-aliveness-ap-lan4.log")
        assert session.pushed == [], "no local image -> no switch push"

    def test_lifeline_broken_refuses(self, tmp_path: Path, capsys) -> None:
        with pytest.raises(ba.AdoptError, match="lifeline not verifiably armed"):
            self._run(["LIFELINE-BROKEN"], tmp_path)
        assert "[PASS] envelope" not in capsys.readouterr().out

    def test_lifeline_ok_but_image_sha_missing_refuses(self, tmp_path: Path) -> None:
        # digest known -> the switch-side sha readback is a required marker
        with pytest.raises(ba.AdoptError, match="IMAGE-SHA-OK"):
            self._run(["LIFELINE-OK", ba.RECORDER_OK,
                       ba.BLANK_CHANNEL_OK], tmp_path, digest="a" * 64)

    def test_recorder_broken_refuses(self, tmp_path: Path) -> None:
        with pytest.raises(ba.AdoptError, match="aliveness recorder not verified"):
            self._run(["LIFELINE-OK", "RECORDER-BROKEN"], tmp_path)

    def test_both_auth_channels_dead_refuses(self, tmp_path: Path) -> None:
        auth_err = "dbclient: Remote closed the connection"
        with pytest.raises(ba.AdoptError, match="would strand"):
            self._run(["LIFELINE-OK", ba.RECORDER_OK,
                       auth_err, auth_err], tmp_path)

    def test_blank_dead_but_key_auth_proves_v6_channel(self, tmp_path, capsys) -> None:
        # live unit has a root password set: blank auth fails, key auth over
        # the same v6 link-local still proves the channel mechanism (the
        # post-reset blank password is rom-audit's ROM guarantee)
        self._run(["LIFELINE-OK", ba.RECORDER_OK,
                   "dbclient: Authentications that can continue: publickey",
                   ba.V6_CHANNEL_OK + "\nextreme-networks,ws-ap3915i"], tmp_path)
        out = capsys.readouterr().out
        assert "key auth" in out and "ROM guarantee" in out

    def test_blank_channel_proof_prints_exact_path(self, tmp_path, capsys) -> None:
        self._run(["LIFELINE-OK", ba.RECORDER_OK,
                   ba.BLANK_CHANNEL_OK], tmp_path)
        assert "blank-password channel proven" in capsys.readouterr().out

    def test_local_image_pushed_to_tftproot(self, tmp_path: Path) -> None:
        img = tmp_path / "rec.bin"
        img.write_bytes(b"image")
        _, _, session = self._run(
            ["LIFELINE-OK\nIMAGE-SHA-OK", ba.RECORDER_OK,
             ba.BLANK_CHANNEL_OK], tmp_path,
            image_path=img, digest="a" * 64)
        assert session.pushed == [(str(img), "/tmp/bench-tftp/rec.bin")]

    def test_lifeline_script_is_exactly_bench_flash_lifeline(self, tmp_path: Path) -> None:
        # REUSE, not duplication: the envelope must send bench_flash's proven
        # lifeline script byte-for-byte (plus, at most, the sha readback)
        import bench_flash
        _, calls, _ = self._run(["LIFELINE-OK", ba.RECORDER_OK,
                                 ba.BLANK_CHANNEL_OK], tmp_path)
        assert calls[0] == ("\n".join(
            bench_flash.lifeline_lines(PLACE, "rec.bin", "/tmp/bench-tftp")) + "\n")

    def test_sha_readback_appended_after_reused_lines(self, tmp_path: Path) -> None:
        import bench_flash
        _, calls, _ = self._run(["LIFELINE-OK\nIMAGE-SHA-OK", ba.RECORDER_OK,
                                 ba.BLANK_CHANNEL_OK], tmp_path, digest="a" * 64)
        base = "\n".join(
            bench_flash.lifeline_lines(PLACE, "rec.bin", "/tmp/bench-tftp"))
        assert calls[0] == base + ("\nsha256sum /tmp/bench-tftp/rec.bin | "
                                   "grep -q " + "a" * 64 +
                                   " && echo IMAGE-SHA-OK || echo IMAGE-SHA-FAIL\n")


class TestRecorderScript:
    """Script invariants for the detached aliveness recorder (#289)."""

    def test_uses_setsid_never_nohup(self) -> None:
        joined = "\n".join(ba.recorder_lines(PLACE))
        assert "setsid" in joined
        assert "nohup" not in joined, \
            "AGENTS.md rule 8: nohup over ssh dies when the session closes"

    def test_detached_output_redirects_off_ssh_pipe(self) -> None:
        setsid_line = next(ln for ln in ba.recorder_lines(PLACE) if "setsid" in ln)
        assert ">/dev/null 2>&1 &" in setsid_line, \
            "an inherited stdout holds the ssh pipe open and blocks switch_sh forever"

    def test_loop_body_carries_no_single_quotes(self) -> None:
        # the body rides inside `setsid sh -c '...'` — a single quote breaks out
        assert "'" not in ba.recorder_loop_body(PLACE, "/tmp/x.log")

    def test_probe_closes_stdin(self) -> None:
        assert "</dev/null" in ba.recorder_loop_body(PLACE, "/tmp/x.log"), \
            "dbclient must not eat the piped script (stdin-eats-script bug)"

    def test_previous_recorder_killed_before_rearm(self) -> None:
        first = ba.recorder_lines(PLACE)[0]
        assert first.startswith("kill $(pgrep")
        assert "bench-aliveness-ap-lan4" in first

    def test_verification_is_fail_closed_marker(self) -> None:
        gate = ba.recorder_lines(PLACE)[-1]
        assert ba.RECORDER_OK in gate and "RECORDER-BROKEN" in gate
        assert "[ -s /tmp/bench-aliveness-ap-lan4.log ]" in gate, \
            "the 'armed' line proves the loop is executing, not just forked"

    def test_log_path_is_per_place(self) -> None:
        other = ba.Place("ap-lan5", "b4:2d:56:24:ad:97", "192.168.105.51")
        assert ba.recorder_log_path(PLACE) == "/tmp/bench-aliveness-ap-lan4.log"
        assert ba.recorder_log_path(other) == "/tmp/bench-aliveness-ap-lan5.log"


class TestRecorderLoopUnderBinSh:
    """The recorder loop body is BusyBox-sh; prove the classification by
    EXECUTING it under /bin/sh with a fake dbclient on PATH (the
    #291 /bin/sh payload-stub pattern)."""

    @pytest.fixture(autouse=True)
    def _fake_dbclient(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "dbclient").write_text('#!/bin/sh\necho "$FAKE_DBCLIENT_OUT"\n')
        (bindir / "dbclient").chmod(0o755)
        monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])

    @pytest.mark.parametrize("probe_out,expected", [
        ("REC-ALIVE", "up"),
        ("dbclient: Connection to root@fe80::b62d:56ff:fe25:79b1%switch.1004:22 "
         "exited: Remote closed the connection", "auth-dead"),
        ("dbclient: Authentications that can continue: publickey,password",
         "auth-dead"),
        ("dbclient: Connection refused", "down"),
        ("dbclient: Connection timed out", "down"),
    ])
    def test_classification(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                            probe_out: str, expected: str) -> None:
        log = tmp_path / "rec.log"
        monkeypatch.setenv("FAKE_DBCLIENT_OUT", probe_out)
        body = ba.recorder_loop_body(PLACE, str(log))
        subprocess.run(["/bin/sh", "-c", body], check=True)
        ts, state = log.read_text().split()
        assert state == expected
        assert ts.isdigit(), "each record is `epoch state`"

    def test_appends_one_line_per_iteration(self, tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
        log = tmp_path / "rec.log"
        monkeypatch.setenv("FAKE_DBCLIENT_OUT", "REC-ALIVE")
        body = ba.recorder_loop_body(PLACE, str(log))
        for _ in range(3):
            subprocess.run(["/bin/sh", "-c", body], check=True)
        assert len(log.read_text().splitlines()) == 3


class TestResetRequiresEnvelope:
    """Fail-closed: stage_reset refuses without a same-session receipt."""

    def test_no_receipt_refuses(self, tmp_path: Path) -> None:
        with pytest.raises(ba.AdoptError, match="recovery envelope"):
            ba.stage_reset(_runner("", tmp_path))

    def test_receipt_for_another_place_refuses(self, tmp_path: Path) -> None:
        wrong = ba.EnvelopeReceipt(
            place="ap-lan2", vlan=1002, tftproot="/tmp/bench-tftp",
            lifeline_log="/tmp/tftp-1002.log",
            recorder_log="/tmp/bench-aliveness-ap-lan2.log")
        with pytest.raises(ba.AdoptError, match="not ap-lan4/switch.1004"):
            ba.stage_reset(_runner("", tmp_path), envelope=wrong)


class TestResolveLifelineImage:
    def _registry(self, tmp_path: Path, version: str = "24.10.2") -> Path:
        import hashlib
        img = tmp_path / "img.bin"
        img.write_bytes(b"firmware")
        reg = tmp_path / "images.json"
        reg.write_text(__import__("json").dumps({"images": {"k": {
            "sha256": hashlib.sha256(img.read_bytes()).hexdigest(),
            "version": version, "profile": "extreme-networks_ws-ap3915i",
            "path": str(img)}}}))
        return reg

    def test_explicit_image_needs_no_registry(self, tmp_path: Path) -> None:
        name, path, digest = ba.resolve_lifeline_image(
            PLACE, tmp_path / "nope.json", "operator-staged.bin")
        assert (name, path, digest) == ("operator-staged.bin", None, "")

    def test_registry_match_gates_and_returns_digest(self, tmp_path: Path) -> None:
        reg = self._registry(tmp_path)
        name, path, digest = ba.resolve_lifeline_image(PLACE, reg, None)
        assert name == "img.bin" and path is not None and len(digest) == 64

    def test_missing_registry_refuses(self, tmp_path: Path) -> None:
        with pytest.raises(ba.AdoptError, match="no recovery image"):
            ba.resolve_lifeline_image(PLACE, tmp_path / "nope.json", None)

    def test_no_matching_release_refuses(self, tmp_path: Path) -> None:
        reg = self._registry(tmp_path, version="23.05.4")
        with pytest.raises(ba.AdoptError, match="no images.json entry"):
            ba.resolve_lifeline_image(PLACE, reg, None)

    def test_corrupt_image_refuses_via_check_image(self, tmp_path: Path) -> None:
        import hashlib
        img = tmp_path / "img.bin"
        img.write_bytes(b"firmware")
        reg = tmp_path / "images.json"
        reg.write_text(__import__("json").dumps({"images": {"k": {
            "sha256": "0" * 64, "version": "24.10.2",
            "profile": "extreme-networks_ws-ap3915i", "path": str(img)}}}))
        with pytest.raises(ba.AdoptError, match="sha256 mismatch"):
            ba.resolve_lifeline_image(PLACE, reg, None)


class TestEnvelopeOrder:
    def test_envelope_precedes_reset_in_order(self) -> None:
        assert ba.ORDER.index("envelope") < ba.ORDER.index("reset")
        assert ba.ORDER.index("rom-audit") < ba.ORDER.index("reset")

    def test_envelope_not_in_bare_stages_mapping(self) -> None:
        # arming needs arguments; main injects a per-run closure instead
        assert "envelope" not in ba.STAGES


class TestCliEnvelopeGate:
    def _reg(self, tmp_path: Path, name: str = "ap-lan9") -> Path:
        reg = tmp_path / "places.json"
        reg.write_text('{"places": [{"name": "%s", "mac": "02:aa:bb:cc:dd:ee", '
                       '"dut_ip": "192.168.109.51"}]}' % name)
        return reg

    @pytest.fixture(autouse=True)
    def _offline_session(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import bench_session
        monkeypatch.setattr(bench_session, "get_session",
                            lambda **kw: FakeSession())

    def test_reset_without_envelope_stage_refused(self, tmp_path: Path,
                                                  capsys) -> None:
        rc = ba.main(["--place", "ap-lan9", "--places", str(self._reg(tmp_path)),
                      "--stages", "reset", "--i-know"])
        assert rc == 2
        assert "envelope" in capsys.readouterr().out

    def test_reset_without_rom_audit_refused(self, tmp_path: Path) -> None:
        rc = ba.main(["--place", "ap-lan9", "--places", str(self._reg(tmp_path)),
                      "--stages", "envelope,reset", "--i-know",
                      "--lifeline-image", "rec.bin"])
        assert rc == 2

    def test_envelope_without_recovery_image_fails(self, tmp_path: Path,
                                                   capsys) -> None:
        rc = ba.main(["--place", "ap-lan9", "--places", str(self._reg(tmp_path)),
                      "--images", str(tmp_path / "no-images.json"),
                      "--stages", "envelope"])
        assert rc == 1
        assert "recovery image" in capsys.readouterr().out

    def test_envelope_then_reset_hands_receipt_through_main(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        # flagship: rc 0 is only possible if the envelope receipt flowed
        # from the envelope stage into gated stage_reset
        canned = iter([
            "root:::0:99999:7:::\n\toption PasswordAuth 'on'\n"
            "\toption RootPasswordAuth 'on'",              # rom-audit
            "LIFELINE-OK",                                  # envelope-lifeline
            ba.RECORDER_OK,                                 # envelope-recorder
            ba.BLANK_CHANNEL_OK + "\nextreme-networks,ws-ap3915i",  # blankpw
            "FIRSTBOOT-RC=0",                               # reset-firstboot (key)
            "FIRSTBOOT-RC=0",                               # reset-firstboot (pw retry)
            "",                                             # reset-reboot
            RESET_FACTORY,                                  # reset-check
        ])

        def transport(_script: str) -> str:
            return next(canned)

        import bench_session
        session = FakeSession()
        session.switch_sh = transport  # type: ignore[method-assign]
        monkeypatch.setattr(bench_session, "get_session", lambda **kw: session)
        monkeypatch.setattr(ba, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(ba.time, "sleep", lambda s: None)
        monkeypatch.setattr(ba.time, "monotonic", lambda: 0)
        rc = ba.main(["--place", "ap-lan9", "--places", str(self._reg(tmp_path)),
                      "--stages", "rom-audit,envelope,reset", "--i-know",
                      "--lifeline-image", "rec.bin"])
        out = capsys.readouterr().out
        assert rc == 0, out
        assert "[PASS] envelope" in out and "[PASS] reset" in out
