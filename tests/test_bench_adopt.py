"""bench_adopt — assertion tests (hardware-safe; canned transports only).

Canned outputs below are REAL captures from the 2026-09-22 ap-lan4 spike,
so the assertions are pinned against ground truth, not fiction.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import bench_adopt as ba

PLACE = ba.Place("ap-lan4", "b4:2d:56:25:79:b1", "192.168.104.51")

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


class TestAdoptFullFlow:
    @pytest.fixture(autouse=True)
    def _no_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ba.time, "sleep", lambda s: None)
        monkeypatch.setattr(ba.time, "monotonic", lambda: 0)

    def test_value_readback_flow_passes(self, tmp_path: Path) -> None:
        canned = [
            "extreme-networks,ws-ap3915i",                          # adopt-ready
            "KEYS-PUSHED\nKEY-AUTH-OK\n3 /etc/dropbear/authorized_keys",  # adopt-keys
            "---READBACK---\nstatic\n192.168.104.51/24\n192.168.104.1\n192.168.104.1",
            "DEADMAN-ARMED\nCOMMITTED\nRESTARTED",
        ]
        ba.stage_adopt(_runner(canned, tmp_path))

    def test_wrong_readback_value_refuses_commit(self, tmp_path: Path) -> None:
        canned = [
            "extreme-networks,ws-ap3915i",
            "KEYS-PUSHED\nKEY-AUTH-OK\n3 /etc/dropbear/authorized_keys",
            "---READBACK---\nstatic\n192.168.1.1/24\n192.168.104.1\n192.168.104.1",
        ]
        with pytest.raises(ba.AdoptError, match="readback mismatch"):
            ba.stage_adopt(_runner(canned, tmp_path))

    def test_staging_reverts_stale_pending_first(self, tmp_path: Path) -> None:
        scripts: list[str] = []
        canned = iter([
            "extreme-networks,ws-ap3915i",
            "KEYS-PUSHED\nKEY-AUTH-OK\n3",
            "---READBACK---\nstatic\n192.168.104.51/24\n192.168.104.1\n192.168.104.1",
            "DEADMAN-ARMED\nCOMMITTED\nRESTARTED",
        ])

        def capture(script: str) -> str:
            scripts.append(script)
            return next(canned)

        ba.stage_adopt(ba.Runner(capture, PLACE, tmp_path / "ev"))
        assert any("uci revert network" in s for s in scripts), \
            "staging must start from a clean baseline"


def _runner(canned: str | list[str], tmp_path: Path, place: ba.Place = PLACE,
            stages_done: set[str] | None = None) -> ba.Runner:
    remaining = list(canned) if isinstance(canned, list) else None

    def serve(_script: str) -> str:
        if remaining is not None:
            if not remaining:
                raise AssertionError("canned transport exhausted")
            return remaining.pop(0)
        return canned  # type: ignore[return-value]

    return ba.Runner(serve, place, tmp_path / "ev", stages_done=stages_done)


ENVELOPE = {"rom-audit", "preflight", "backup", "overlay"}


def _armed_runner(canned: str | list[str], tmp_path: Path,
                  place: ba.Place = PLACE) -> ba.Runner:
    """Runner whose session already established the reset envelope."""
    return _runner(canned, tmp_path, place, stages_done=set(ENVELOPE))


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
    # dut_with_fallback consumes one output per auth attempt; the reboot
    # now rides inside the firstboot command, so no third output exists.
    ARM = ["FIRSTBOOT-RC=0", "FIRSTBOOT-RC=0"]

    def _no_sleep(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ba.time, "sleep", lambda s: None)
        # 10s steps: the auth-death path needs 12+ in-window poll iterations
        # (4 per deliberate PoE cycle, 2 cycles, 4 to raise) under one
        # 240s deadline.
        ticks = iter([0] + [10 * i for i in range(1, 60)] + [9999])
        monkeypatch.setattr(ba.time, "monotonic", lambda: next(ticks))

    def test_keys_surviving_means_not_wiped(self, tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
        self._no_sleep(monkeypatch)
        with pytest.raises(ba.AdoptError, match="overlay was NOT wiped"):
            ba.stage_reset(_armed_runner(self.ARM + [RESET_NOT_WIPED], tmp_path))

    def test_nonzero_firstboot_rc_fails_fast(self, tmp_path: Path) -> None:
        with pytest.raises(ba.AdoptError, match="nonzero"):
            ba.stage_reset(_armed_runner(["FIRSTBOOT-RC=1", "FIRSTBOOT-RC=1"], tmp_path))

    def test_factory_state_passes(self, tmp_path: Path,
                                  monkeypatch: pytest.MonkeyPatch) -> None:
        self._no_sleep(monkeypatch)
        ba.stage_reset(_armed_runner(self.ARM + [RESET_FACTORY], tmp_path))

    def test_mid_reboot_noise_then_factory(self, tmp_path: Path,
                                           monkeypatch: pytest.MonkeyPatch) -> None:
        self._no_sleep(monkeypatch)
        noise = ("dbclient: Connection to root@fe80::...%switch.1003:22 exited: "
                 "Remote closed the connection\n")
        ba.stage_reset(_armed_runner(self.ARM + [noise, noise, RESET_FACTORY], tmp_path))

    def test_persistent_auth_death_fails_fast(self, tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
        self._no_sleep(monkeypatch)
        noise = ("dbclient: Connection to root@fe80::...%switch.1002:22 exited: "
                 "Remote closed the connection\n")
        # 4 auth-dead reset-checks per deliberate PoE cycle + the poe-cycle
        # script itself consumes one canned output; 2 cycles, then 4 more
        # for the console-required abort: 14 canned outputs after firstboot.
        with pytest.raises(ba.AdoptError, match="(?i)console required"):
            ba.stage_reset(_armed_runner(self.ARM + [noise] * 14, tmp_path))


    def test_reboot_rides_in_the_firstboot_command(self, tmp_path: Path,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
        self._no_sleep(monkeypatch)
        scripts: list[str] = []
        canned = iter(self.ARM + [RESET_FACTORY])

        def capture(script: str) -> str:
            scripts.append(script)
            return next(canned)

        ba.stage_reset(ba.Runner(capture, PLACE, tmp_path / "ev", stages_done=set(ENVELOPE)))
        firstboot = next(s for s in scripts if "firstboot" in s)
        assert "reboot" in firstboot, \
            "reboot must be issued in the SAME command — no key-auth channel " \
            "exists after the overlay wipe"

    def test_reset_refused_without_session_envelope(self, tmp_path: Path) -> None:
        with pytest.raises(ba.AdoptError, match="recovery envelope"):
            ba.stage_reset(_runner(self.ARM + [RESET_FACTORY], tmp_path))

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
            "KEYS-PUSHED\nKEY-AUTH-OK\n3",
            "---READBACK---\nstatic\n192.168.104.51/24\n192.168.104.1\n192.168.104.1",
            "DEADMAN-ARMED\nCOMMITTED\nRESTARTED",
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
