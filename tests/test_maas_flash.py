"""Tests for scripts/maas_flash.py safety gates (PR #322 Codex findings).

Covers: publisher-digest gate, serial-whitelist requirement, byte-sized
lsblk parsing with sysfs fallback, streamed+checked decompression,
tail verification, and resize/copy failure aborts — all without any
block device.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import maas_flash  # noqa: E402


def _args(**kw) -> SimpleNamespace:
    base = dict(
        disk="/dev/null",
        image="/dev/null",
        user_data=None,
        network_config=None,
        partition_size=None,
        serial_whitelist="SER1",
        expected_sha256="a" * 64,
        beacon_ip=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _write_image(tmp_path: Path, data: bytes = b"x" * 65536) -> Path:
    p = tmp_path / "img.img"
    p.write_bytes(data)
    return p


# -- gate: expected digest ----------------------------------------------------


def test_missing_expected_sha256_refuses_before_any_disk_work(tmp_path, monkeypatch, capsys):
    img = _write_image(tmp_path)
    called = []
    monkeypatch.setattr(maas_flash, "verify_disk", lambda *a, **k: called.append(a) or (True, "v"))
    rc = maas_flash.flash_and_provision(_args(image=str(img), expected_sha256=""))
    assert rc == 1
    assert "sha256" in capsys.readouterr().err.lower()
    assert not called


def test_digest_mismatch_refuses(tmp_path, monkeypatch, capsys):
    img = _write_image(tmp_path)
    called = []
    monkeypatch.setattr(maas_flash, "verify_disk", lambda *a, **k: called.append(a) or (True, "v"))
    rc = maas_flash.flash_and_provision(_args(image=str(img), expected_sha256="b" * 64))
    assert rc == 1
    err = capsys.readouterr().err.lower()
    assert "mismatch" in err
    assert not called


# -- gate: serial whitelist ---------------------------------------------------


def test_missing_serial_whitelist_refuses(tmp_path, monkeypatch, capsys):
    img = _write_image(tmp_path)
    monkeypatch.setattr(maas_flash, "sha256_file", lambda p, **k: "a" * 64)
    called = []
    monkeypatch.setattr(maas_flash, "verify_disk", lambda *a, **k: called.append(a) or (True, "v"))
    rc = maas_flash.flash_and_provision(_args(image=str(img), serial_whitelist=None))
    assert rc == 1
    assert "whitelist" in capsys.readouterr().err.lower()
    assert not called


def test_blank_serial_whitelist_entries_refuse(tmp_path, monkeypatch, capsys):
    img = _write_image(tmp_path)
    monkeypatch.setattr(maas_flash, "sha256_file", lambda p, **k: "a" * 64)
    called = []
    monkeypatch.setattr(maas_flash, "verify_disk", lambda *a, **k: called.append(a) or (True, "v"))
    rc = maas_flash.flash_and_provision(_args(image=str(img), serial_whitelist=" , "))
    assert rc == 1
    assert not called


# -- disk size parsing --------------------------------------------------------


def test_lsblk_requests_bytes():
    cmds = []

    def fake_run(cmd, **kw):
        cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="32G", stderr="")

    orig = maas_flash.run
    maas_flash.run = fake_run
    try:
        maas_flash.get_disk_info("/dev/sdb")
    finally:
        maas_flash.run = orig
    assert cmds
    for cmd in cmds:
        assert any("-b" in flag for flag in cmd), "lsblk must request byte-sized SIZE output"


def test_human_readable_size_falls_back_to_sysfs(tmp_path, monkeypatch):
    fake_sys = tmp_path / "sys" / "block"
    (fake_sys / "sdb").mkdir(parents=True)
    # 62_500_000 sectors * 512 = 32 GB
    (fake_sys / "sdb" / "size").write_text("62500000\n")
    monkeypatch.setattr(maas_flash, "SYS_BLOCK", fake_sys)
    assert maas_flash.resolve_size_bytes({"size": "32G"}, "sdb") == 32_000_000_000


def test_byte_size_string_parses_directly(tmp_path, monkeypatch):
    monkeypatch.setattr(maas_flash, "SYS_BLOCK", tmp_path / "nonexistent")
    assert maas_flash.resolve_size_bytes({"size": "32000000000"}, "sdb") == 32_000_000_000


def test_unparseable_size_without_sysfs_is_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(maas_flash, "SYS_BLOCK", tmp_path / "nonexistent")
    assert maas_flash.resolve_size_bytes({"size": "465.8G"}, "sdb") == 0


# -- end-to-end (faked command layer, real files) -----------------------------


def _fake_env(tmp_path, monkeypatch, run_results=None, subprocess_behavior=None,
              run_behavior=None):
    """Patch run()/subprocess.run/time.sleep for a full pipeline run."""
    boot = tmp_path / "boot"
    boot.mkdir()
    monkeypatch.setattr(maas_flash, "MOUNT_POINT", str(boot))
    monkeypatch.setattr(maas_flash, "verify_disk", lambda dev, wl: (True, "verified"))
    monkeypatch.setattr(maas_flash.time, "sleep", lambda s: None)
    executed = []

    def fake_run(cmd, **kw):
        executed.append(cmd[0])
        if run_behavior is not None:
            return run_behavior(cmd, **kw)
        rc = (run_results or {}).get(cmd[0], 0)
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="boom")

    monkeypatch.setattr(maas_flash, "run", fake_run)

    def fake_subprocess_run(cmd, **kw):
        behavior = subprocess_behavior or (lambda cmd, kw: None)
        out = behavior(cmd, kw)
        if out is not None:
            return out
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(maas_flash.subprocess, "run", fake_subprocess_run)
    return executed


def test_nonxz_pipeline_streams_and_verifies(tmp_path, monkeypatch, capsys):
    data = bytes(range(256)) * 512  # 128 KiB image
    img = _write_image(tmp_path, data)
    disk = tmp_path / "disk.bin"
    monkeypatch.setattr(
        maas_flash, "sha256_file", lambda p, **k: hashlib.sha256(data).hexdigest()
    )
    _fake_env(tmp_path, monkeypatch)
    rc = maas_flash.flash_and_provision(
        _args(disk=str(disk), image=str(img), expected_sha256=hashlib.sha256(data).hexdigest())
    )
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "USB DISK READY" in out
    assert "last 256MB MATCH" in out
    assert disk.read_bytes() == data


def test_xz_pipeline_streams_to_disk_and_checks_decompressor(tmp_path, monkeypatch, capsys):
    img = tmp_path / "img.img.xz"
    img.write_bytes(b"fake archive")
    disk = tmp_path / "disk.bin"
    monkeypatch.setattr(maas_flash, "sha256_file", lambda p, **k: "a" * 64)
    payload = b"y" * 8192
    payload_sha = hashlib.sha256(payload).hexdigest()

    def behavior(cmd, kw):
        if cmd[0] == "xz":
            return subprocess.CompletedProcess(
                cmd, 0, stdout="file\t1\t1\t100\t8192\t0.1\tCRC64\t0\t0\n", stderr=""
            )
        if cmd[0] == "xzcat":
            stdout = kw.get("stdout")
            assert hasattr(stdout, "write"), "xzcat must stream into the device file"
            assert stdout is not subprocess.PIPE
            assert kw.get("check") is True, "xzcat status must be checked"
            stdout.write(payload)
            return subprocess.CompletedProcess(cmd, 0)
        return None

    def fake_run(cmd, **kw):
        if cmd[0] == "bash":  # verification pipelines
            return subprocess.CompletedProcess(cmd, 0, stdout=payload_sha + "  -\n", stderr="")
        if cmd[0] == "xz":
            return subprocess.CompletedProcess(
                cmd, 0, stdout="file\t1\t1\t100\t8192\t0.1\tCRC64\t0\t0\n", stderr=""
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    _fake_env(tmp_path, monkeypatch, subprocess_behavior=behavior, run_behavior=fake_run)
    rc = maas_flash.flash_and_provision(_args(disk=str(disk), image=str(img)))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert disk.read_bytes() == payload


def test_xz_decompression_failure_aborts(tmp_path, monkeypatch, capsys):
    img = tmp_path / "img.img.xz"
    img.write_bytes(b"truncated")

    def behavior(cmd, kw):
        if cmd[0] == "xzcat":
            raise subprocess.CalledProcessError(1, cmd)
        return None

    monkeypatch.setattr(maas_flash, "sha256_file", lambda p, **k: "a" * 64)
    _fake_env(tmp_path, monkeypatch, subprocess_behavior=behavior)
    rc = maas_flash.flash_and_provision(
        _args(disk=str(tmp_path / "disk.bin"), image=str(img))
    )
    assert rc == 1
    assert "decompression" in capsys.readouterr().err.lower()


# -- resize / injection failure handling --------------------------------------


def _run_resize_case(tmp_path, monkeypatch, capsys, fail_rcs):
    data = b"z" * 65536
    img = _write_image(tmp_path, data)
    monkeypatch.setattr(
        maas_flash, "sha256_file", lambda p, **k: hashlib.sha256(data).hexdigest()
    )
    _fake_env(tmp_path, monkeypatch, run_results=fail_rcs)
    return maas_flash.flash_and_provision(
        _args(
            disk=str(tmp_path / "disk.bin"),
            image=str(img),
            partition_size="50G",
            expected_sha256=hashlib.sha256(data).hexdigest(),
        )
    )


def test_sfdisk_failure_aborts(tmp_path, monkeypatch, capsys):
    rc = _run_resize_case(tmp_path, monkeypatch, capsys, {"bash": 1})
    assert rc == 1
    assert "sfdisk" in capsys.readouterr().err


def test_e2fsck_hard_failure_aborts(tmp_path, monkeypatch, capsys):
    rc = _run_resize_case(tmp_path, monkeypatch, capsys, {"e2fsck": 4})
    assert rc == 1
    assert "e2fsck" in capsys.readouterr().err


def test_resize2fs_failure_aborts(tmp_path, monkeypatch, capsys):
    rc = _run_resize_case(tmp_path, monkeypatch, capsys, {"resize2fs": 1})
    assert rc == 1
    assert "resize2fs" in capsys.readouterr().err


def test_failed_user_data_copy_aborts_without_ready_banner(tmp_path, monkeypatch, capsys):
    data = b"z" * 65536
    img = _write_image(tmp_path, data)
    executed = _fake_env(tmp_path, monkeypatch, run_results={"cp": 1})
    rc = maas_flash.flash_and_provision(
        _args(
            disk=str(tmp_path / "disk.bin"),
            image=str(img),
            user_data=str(img),
            expected_sha256=hashlib.sha256(data).hexdigest(),
        )
    )
    out, err = capsys.readouterr()
    assert rc == 1
    assert "user-data" in err
    assert "USB DISK READY" not in out
    assert "umount" in executed
