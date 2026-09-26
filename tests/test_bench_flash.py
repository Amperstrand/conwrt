"""bench_flash — gate and recovery tests (hardware-safe; canned transports).

Canned outputs mirror the ap-lan4 evidence captures; gate order and the
never-re-flash recovery policy are the behaviors under test.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable

import pytest

import bench_adopt as ba
import bench_flash as bf

PLACE = ba.Place("ap-lan4", "b4:2d:56:25:79:b1", "192.168.104.51")
NO_RESET = ba.Place("ap-lan5", "b4:2d:56:24:ad:97", "192.168.105.51",
                    reset_allowed=False)


def _image_entry(tmp_path: Path, content: bytes = b"firmware-image-bytes") -> tuple[dict[str, str], Path]:
    img = tmp_path / "openwrt-24.10.2-...-ws-ap3915i-squashfs-sysupgrade.bin"
    img.write_bytes(content)
    entry = {"sha256": hashlib.sha256(content).hexdigest(),
             "version": "24.10.2", "profile": bf.EXPECTED_PROFILE}
    return entry, img


class TestImageGates:
    def test_stock_24_and_25_pass(self, tmp_path: Path) -> None:
        entry, img = _image_entry(tmp_path)
        assert bf.check_image({**entry, "version": "25.12.5"}, img)

    @pytest.mark.parametrize("version", ["23.05.5", "26.3.0", "24-snapshot", ""])
    def test_non_stock_refused(self, tmp_path: Path, version: str) -> None:
        entry, img = _image_entry(tmp_path)
        with pytest.raises(ba.AdoptError, match="not stock"):
            bf.check_image({**entry, "version": version}, img)

    def test_wrong_profile_refused(self, tmp_path: Path) -> None:
        entry, img = _image_entry(tmp_path)
        with pytest.raises(ba.AdoptError, match="profile"):
            bf.check_image({**entry, "profile": "dlink_covr-x1860-a1"}, img)

    def test_sha_mismatch_refused(self, tmp_path: Path) -> None:
        entry, img = _image_entry(tmp_path)
        with pytest.raises(ba.AdoptError, match="sha256 mismatch"):
            bf.check_image({**entry, "sha256": "0" * 64}, img)

    def test_missing_file_refused(self, tmp_path: Path) -> None:
        entry, _ = _image_entry(tmp_path)
        with pytest.raises(ba.AdoptError, match="image file missing"):
            bf.check_image(entry, tmp_path / "ghost.bin")

    def test_missing_field_refused(self, tmp_path: Path) -> None:
        entry, img = _image_entry(tmp_path)
        del entry["sha256"]
        with pytest.raises(ba.AdoptError, match="missing 'sha256'"):
            bf.check_image(entry, img)


class TestLifelineLines:
    def test_firewall_rule_precedes_tftp_server(self) -> None:
        lines = bf.lifeline_lines(PLACE, "img.bin", "/tmp/bench-tftp")
        joined = "\n".join(lines)
        assert "switch.1004" in joined and "tftp-root=/tmp/bench-tftp" in joined
        assert "LIFELINE-OK" in joined
        assert joined.index("nft insert rule") < joined.index("dnsmasq")


class _Spy:
    def __init__(self, outputs: Callable[[], str] | list[str]) -> None:
        self.outputs: Callable[[], str] | None = outputs if callable(outputs) else None
        self.queue: list[str] = [] if self.outputs is not None else list(outputs)
        self.scripts: list[str] = []

    def __call__(self, script: str) -> str:
        self.scripts.append(script)
        if self.outputs is not None:
            return self.outputs()
        if not self.queue:
            raise AssertionError("canned transport exhausted")
        return self.queue.pop(0)


def _no_time(monkeypatch: pytest.MonkeyPatch, ticks: list[float]) -> None:
    monkeypatch.setattr(bf.time, "sleep", lambda s: None)
    monkeypatch.setattr(bf.time, "monotonic", lambda: ticks.pop(0) if ticks else 9e9)


class FakeSession:
    """BenchSession double: records switch_put / power order (the safety
    seams under test) without touching any transport."""

    def __init__(self) -> None:
        self.puts: list[tuple[str, str]] = []
        self.cycles: list[str] = []

    def switch_put(self, local: Path, remote: str) -> None:
        self.puts.append((str(local), remote))

    def power(self, place, action: str) -> None:
        self.cycles.append(action)


class TestFlashHappyPath:
    def test_full_gated_flow(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        entry, img = _image_entry(tmp_path)
        digest = entry["sha256"]
        _no_time(monkeypatch, [0, 20, 40])
        fake = FakeSession()
        spy = _Spy([
            f"FLASH-TARGET-OK\n{PLACE.board}",   # flash-target
            "LIFELINE-OK",                               # flash-lifeline
            digest,                                      # flash-push readback
            "",                                          # flash-go
            f"No such file\n{digest[:8]}\nVERSION-MATCH",  # flash-check
        ])
        r = ba.Runner(spy, PLACE, tmp_path / "ev")  # type: ignore[arg-type]
        bf.stage_flash(r, entry, img, "/tmp/bench-tftp", fake)
        all_scripts = "\n".join(spy.scripts)
        assert "sysupgrade -n" in all_scripts
        assert " -F" not in all_scripts and "--force" not in all_scripts
        assert fake.puts == [(str(img), "/tmp/bench-tftp/" + img.name)]
        assert fake.cycles == [], "happy path must never power-cycle"

    def test_reset_refused_for_gated_place(self, tmp_path: Path) -> None:
        entry, img = _image_entry(tmp_path)
        fake = FakeSession()
        spy = _Spy([])
        r = ba.Runner(spy, NO_RESET, tmp_path / "ev")  # type: ignore[arg-type]
        with pytest.raises(ba.AdoptError, match="refused"):
            bf.stage_flash(r, entry, img, "/tmp/t", fake)
        assert spy.scripts == [], "refusal must happen before any device contact"
        assert fake.puts == [] and fake.cycles == []


class TestFlashRecoveryPolicy:
    def test_broken_lifeline_never_flashes(self, tmp_path: Path) -> None:
        entry, img = _image_entry(tmp_path)
        fake = FakeSession()
        spy = _Spy([f"FLASH-TARGET-OK\n{PLACE.board}", "LIFELINE-BROKEN"])
        r = ba.Runner(spy, PLACE, tmp_path / "ev")  # type: ignore[arg-type]
        with pytest.raises(ba.AdoptError, match="lifeline"):
            bf.stage_flash(r, entry, img, "/tmp/t", fake)
        assert len(spy.scripts) == 2, "must stop at the lifeline gate — no push, no flash"
        assert "sysupgrade -n" not in "\n".join(spy.scripts)
        assert fake.puts == [(str(img), f"/tmp/t/{img.name}")], \
            "image staging on the switch precedes lifeline verification (HEAD order)"
        assert fake.cycles == [], "a broken lifeline must never trigger the recovery cycle"

    def test_silent_unit_cycles_once_then_stops(self, tmp_path: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
        entry, img = _image_entry(tmp_path)
        digest = entry["sha256"]
        fake = FakeSession()
        _no_time(monkeypatch, [0, 200, 220, 240, 260, 280, 300, 320, 340])
        preamble = [f"FLASH-TARGET-OK\n{PLACE.board}", "LIFELINE-OK", digest, ""]

        def sequenced() -> str:
            if preamble:
                return preamble.pop(0)
            return "dbclient: Remote closed the connection"

        r = ba.Runner(_Spy(sequenced), PLACE, tmp_path / "ev")  # type: ignore[arg-type]
        with pytest.raises(ba.AdoptError, match="do not re-flash"):
            bf.stage_flash(r, entry, img, "/tmp/t", fake)
        assert fake.cycles == ["cycle"], "exactly one recovery power cycle allowed"


class TestMethodPlumbing:
    def test_flash_method_requires_image_key(self, tmp_path: Path) -> None:
        reg = tmp_path / "places.json"
        reg.write_text('{"places": [{"name": "ap-x", "mac": "02:aa:bb:cc:dd:ee", '
                       '"dut_ip": "192.168.109.51"}]}')
        rc = ba.main(["--place", "ap-x", "--places", str(reg),
                      "--method", "flash", "--i-know"])
        assert rc == 2

    def test_flash_method_rejects_unknown_image(self, tmp_path: Path) -> None:
        reg = tmp_path / "places.json"
        reg.write_text('{"places": [{"name": "ap-x", "mac": "02:aa:bb:cc:dd:ee", '
                       '"dut_ip": "192.168.109.51"}]}')
        imgs = tmp_path / "images.json"
        imgs.write_text('{"images": {}}')
        rc = ba.main(["--place", "ap-x", "--places", str(reg),
                      "--images", str(imgs),
                      "--method", "flash", "--image", "ghost", "--i-know"])
        assert rc == 2

    def test_flash_method_clean_refusal_without_registry(self, tmp_path: Path) -> None:
        reg = tmp_path / "places.json"
        reg.write_text('{"places": [{"name": "ap-x", "mac": "02:aa:bb:cc:dd:ee", '
                       '"dut_ip": "192.168.109.51"}]}')
        rc = ba.main(["--place", "ap-x", "--places", str(reg),
                      "--images", str(tmp_path / "nope.json"),
                      "--method", "flash", "--image", "any", "--i-know"])
        assert rc == 2


class TestBoardGate:
    def test_board_name_comma_form_is_the_gate(self, tmp_path: Path,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
        """/tmp/sysinfo/board_name prints the DT compatible string (commas),
        not the ImageBuilder profile (underscores) — the gate must match the
        wire form a real AP3915i emits."""
        entry, img = _image_entry(tmp_path)
        fake = FakeSession()
        spy = _Spy([f"FLASH-TARGET-OK\n{PLACE.board}", "LIFELINE-BROKEN"])
        r = ba.Runner(spy, PLACE, tmp_path / "ev")  # type: ignore[arg-type]
        with pytest.raises(ba.AdoptError, match="lifeline"):  # passes board gate, stops later
            bf.stage_flash(r, entry, img, "/tmp/t", fake)

    def test_underscore_profile_form_alone_fails_the_gate(self, tmp_path: Path) -> None:
        entry, img = _image_entry(tmp_path)
        fake = FakeSession()
        spy = _Spy([f"FLASH-TARGET-OK\n{bf.EXPECTED_PROFILE}"])
        r = ba.Runner(spy, PLACE, tmp_path / "ev")  # type: ignore[arg-type]
        with pytest.raises(ba.AdoptError, match="not reachable/verified"):
            bf.stage_flash(r, entry, img, "/tmp/t", fake)


class TestFirmwareStdin:
    def test_image_push_keeps_firmware_as_dbclient_stdin(self, tmp_path: Path,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
        """The push line must carry exactly ONE stdin redirect — the firmware
        file. A trailing </dev/null (stdin-eats-script guard) overrides it
        left-to-right and streams an empty image."""
        entry, img = _image_entry(tmp_path)
        digest = entry["sha256"]
        fake = FakeSession()
        spy = _Spy([f"FLASH-TARGET-OK\n{PLACE.board}", "LIFELINE-OK", digest, "",
                    f"No such file\\n{digest[:8]}\\nVERSION-MATCH"])
        _no_time(monkeypatch, [0, 20, 40])
        r = ba.Runner(spy, PLACE, tmp_path / "ev")  # type: ignore[arg-type]
        bf.stage_flash(r, entry, img, "/tmp/t", fake)
        push = spy.scripts[2]
        push_lines = [l for l in push.splitlines() if "cat > " in l]
        assert push_lines, "push script must contain the cat transfer line"
        line = push_lines[0]
        assert f"< /tmp/t/{img.name}" in line and "dev/null" not in line, \
            "the firmware redirect must be the final stdin redirect"
