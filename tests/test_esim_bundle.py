"""Tests for conwrt esim-bundle — the no-internet toolchain side-loader (#856).

The bundle driver verifies lpac-openwrt artifacts (sha256 + fingerprints
+ trust store) and side-loads them. Tests build synthetic tarballs with
the REAL bundle shape (non-invasive layout, private libs, GSMA CI store)
— both valid and deliberately-corrupted classes.
"""
from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from conwrt import cmd_esim_bundle  # noqa: E402
from conwrt.cmd_esim_bundle import (  # noqa: E402
    REQUIRED_DRIVERS,
    REQUIRED_FINGERPRINTS,
    TRUST_STORE_PATH,
    BundleError,
    verify_artifact,
)


def _fake_driver(name: str) -> bytes:
    """A driver .so carrying the fingerprints for its member path."""
    body = b"\x7fELF" + name.encode() + b"\x00"
    for member, fps in REQUIRED_FINGERPRINTS.items():
        if name in member:
            for fp in fps:
                body += fp + b"\x00"
    return body + b"\x00" * 32


def _fake_ca_bundle(n: int = 123) -> bytes:
    return (b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n") * n


def build_bundle(tmp_path: Path, *, binary: bytes | None = None,
                 ca_certs: int = 123, drivers: list[str] | None = None,
                 include_ca: bool = True) -> Path:
    """Build a synthetic lpac-openwrt-shaped tarball."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add(name: str, data: bytes, mode: int = 0o755):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))

        add("./usr/bin/lpac", binary or b"\x7fELF-lpac\x00")
        for d in (drivers or REQUIRED_DRIVERS):
            add(f"./usr/lib/lpac/driver/{d}", _fake_driver(d))
        add("./usr/lib/lpac/lib/libcurl.so.4", b"\x7fELF-curl\x00")
        add("./usr/lib/lpac/lib/libssl.so.3", b"\x7fELF-ssl\x00")
        if include_ca:
            add(f"./{TRUST_STORE_PATH}", _fake_ca_bundle(ca_certs), mode=0o644)

    path = tmp_path / "lpac-25.12.6-mipsel24kc-r1.tar.gz"
    path.write_bytes(buf.getvalue())
    (tmp_path / "lpac-25.12.6-mipsel24kc-r1.tar.gz.sha256").write_text(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}\n")
    return path


class TestVerifyArtifact:
    def test_valid_bundle(self, tmp_path):
        art = build_bundle(tmp_path)
        m = verify_artifact(art)
        assert m["entries"] >= 6
        assert m["ca_certs"] == 123
        assert m["sha256"] == hashlib.sha256(art.read_bytes()).hexdigest()

    def test_missing_file(self, tmp_path):
        with pytest.raises(BundleError, match="not found"):
            verify_artifact(tmp_path / "nonexistent.tar.gz")

    def test_sha_mismatch(self, tmp_path):
        art = build_bundle(tmp_path)
        # tamper with the sidecar
        sidecar = art.with_suffix(art.suffix + ".sha256")
        sidecar.write_text("0" * 64 + f"  {art}\n")
        with pytest.raises(BundleError, match="sha256 mismatch"):
            verify_artifact(art)

    def test_missing_driver(self, tmp_path):
        art = build_bundle(tmp_path, drivers=["driver_apdu_at_csim.so"])
        with pytest.raises(BundleError, match="driver_http_curl.so"):
            verify_artifact(art)

    def test_missing_fingerprint(self, tmp_path):
        # at_csim driver present but WITHOUT the uppercase-hex fingerprint
        art = build_bundle(tmp_path, binary=b"\x00" * 128)
        # rebuild with a stripped driver
        import io, tarfile as tf
        buf = io.BytesIO()
        with tarfile.open(art, "r:gz") as src:
            with tf.open(fileobj=buf, mode="w:gz") as dst:
                for member in src.getmembers():
                    data = src.extractfile(member).read() if member.isfile() else None
                    if "driver_apdu_at_csim" in member.name and data:
                        data = data.replace(b"LPAC_APDU_AT_HEX", b"XXXXXXXXXXXX")
                    if data is not None:
                        info = tf.TarInfo(name=member.name)
                        info.size = len(data)
                        info.mode = member.mode
                        dst.addfile(info, io.BytesIO(data))
        stripped = tmp_path / "stripped.tar.gz"
        stripped.write_bytes(buf.getvalue())
        with pytest.raises(BundleError, match="LPAC_APDU_AT_HEX"):
            verify_artifact(stripped)

    def test_missing_trust_store(self, tmp_path):
        art = build_bundle(tmp_path, include_ca=False)
        with pytest.raises(BundleError, match="trust store"):
            verify_artifact(art)

    def test_thin_trust_store(self, tmp_path):
        art = build_bundle(tmp_path, ca_certs=5)  # only the GSMA anchors
        with pytest.raises(BundleError, match="only 5 certs"):
            verify_artifact(art)


class TestCmdEsimBundle:
    def _args(self, artifact, **kw):
        base = dict(artifact=str(artifact), verify_only=False, push=None)
        base.update(kw)
        return SimpleNamespace(**base)

    def test_verify_only(self, tmp_path, capsys):
        art = build_bundle(tmp_path)
        assert cmd_esim_bundle.cmd_esim_bundle(
            self._args(art, verify_only=True)) == 0
        out = capsys.readouterr().out
        assert "verified:" in out and "123 CA certs" in out

    def test_default_prints_pasteable_commands(self, tmp_path, capsys):
        art = build_bundle(tmp_path)
        assert cmd_esim_bundle.cmd_esim_bundle(self._args(art)) == 0
        out = capsys.readouterr().out
        assert "scp -O" in out
        assert "tar -xzf" in out and "lpac version" in out
        assert "LPAC_APDU=at_csim" in out
        assert "LPAC_APDU_AT_HEX=UPPER" in out
        assert "Gate 0" in out
        assert "esim-http-relay" in out

    def test_corrupted_artifact_refused(self, tmp_path, capsys):
        art = build_bundle(tmp_path)
        sidecar = art.with_suffix(art.suffix + ".sha256")
        sidecar.write_text("f" * 64 + f"  {art}\n")
        rc = cmd_esim_bundle.cmd_esim_bundle(self._args(art))
        assert rc == 1
        assert "sha256 mismatch" in capsys.readouterr().err

    def test_push_failure(self, tmp_path, monkeypatch, capsys):
        art = build_bundle(tmp_path)
        monkeypatch.setattr(cmd_esim_bundle.subprocess, "run",
                            lambda *a, **k: subprocess.CompletedProcess(
                                [], 1, stdout="", stderr="no route"))
        rc = cmd_esim_bundle.cmd_esim_bundle(self._args(art, push="1.2.3.4"))
        assert rc == 1
        assert "scp failed" in capsys.readouterr().err

    def test_push_success(self, tmp_path, monkeypatch, capsys):
        art = build_bundle(tmp_path)
        calls = []

        def fake_run(argv, **kw):
            calls.append(list(argv))
            if argv[0] == "scp":
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(
                argv, 0, stdout="lpac 2.3.0\nBUNDLE-INSTALLED", stderr="")

        monkeypatch.setattr(cmd_esim_bundle.subprocess, "run", fake_run)
        rc = cmd_esim_bundle.cmd_esim_bundle(self._args(art, push="192.168.5.1"))
        assert rc == 0
        assert calls[0][0] == "scp" and calls[0][1] == "-O"
        assert "tar -xzf" in calls[1][-1]
        out = capsys.readouterr().out
        assert "installed on 192.168.5.1" in out
        assert "LPAC_APDU=at_csim" in out
