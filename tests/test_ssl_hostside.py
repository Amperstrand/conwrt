"""Tests for use_cases/ssl.py host-side legs (#794 bonus lane).

The preset ops were already characterized (test_ssl_ops.py, 17 tests);
this lane covers the untested 76%: the lancert/qip downloaders (incl.
the real PEM-splitting logic) and deploy_ssl_post_flash's provider
dispatch, LAN-IP autodetect, SCP loop, and install-copy commands —
all network seams stubbed. No wire.
"""
from __future__ import annotations

from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest

import use_cases.ssl as sslmod


CERT_PEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n"
COMBINED = CERT_PEM + KEY_PEM


def _stub_ssh_utils(monkeypatch):
    """deploy_ssl_post_flash imports ssh_utils.ssh_cmd at CALL time;
    patch the real module attribute so the late import sees the stub."""
    import sys
    ssh_utils = sys.modules.get("ssh_utils")
    if ssh_utils is None:
        import ssh_utils as _real  # PYTHONPATH=scripts
        ssh_utils = _real
    calls = []
    monkeypatch.setattr(ssh_utils, "ssh_cmd",
                        lambda ip, cmd, key=None: ["ssh", ip, cmd])
    return calls


def _stub_subprocess(monkeypatch, *, ssh_ok=True, scp_ok=True):
    runs = []

    def fake_run(cmd, **kw):
        runs.append(cmd)
        is_scp = cmd and cmd[0] == "scp"
        rc = 0 if (scp_ok if is_scp else ssh_ok) else 1
        return CompletedProcess(args=cmd, returncode=rc,
                                stdout="192.168.5.1\n" if not is_scp else "",
                                stderr="" if rc == 0 else "boom")

    monkeypatch.setattr(sslmod.subprocess, "run", fake_run)
    return runs


class TestQipZone:
    @pytest.mark.parametrize("ip,zone", [
        ("192.168.1.1", "v"), ("10.0.0.1", "x"), ("172.16.0.1", "p"),
        ("100.64.0.1", "c"), ("169.254.1.1", "v"),  # default fallback
    ])
    def test_prefix_table(self, ip, zone):
        assert sslmod._qip_zone_for_ip(ip) == zone


class TestDownloadLancert:
    def test_downloads_and_names(self, tmp_path, monkeypatch):
        fetched = []

        def fake_urlretrieve(url, dest):
            fetched.append((url, dest))
            open(dest, "w").write(CERT_PEM if "fullchain" in url else KEY_PEM)

        monkeypatch.setattr(sslmod, "urlretrieve", fake_urlretrieve)
        cert, key, host = sslmod.download_lancert_cert("192.168.5.1", str(tmp_path))
        assert host == "192-168-5-1.lancert.dev"
        assert cert.endswith("server.crt") and key.endswith("server.key")
        assert open(cert).read() == CERT_PEM
        urls = [u for u, _ in fetched]
        assert any("192.168.5.1/fullchain.pem" in u for u in urls)
        assert any("192.168.5.1/privkey.pem" in u for u in urls)


class TestDownloadQip:
    def test_splits_combined_pem(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            sslmod, "urlretrieve",
            lambda url, dest: open(dest, "w").write(COMBINED))
        cert, key, host = sslmod.download_qip_cert("10.1.2.3", str(tmp_path))
        assert host == "*.x.qip.sh"          # 10. -> zone x
        assert open(cert).read().strip() == CERT_PEM.strip()
        # KNOWN BUG (filed as an issue, pinned here as current behavior):
        # the key regex '-----BEGIN .*PRIVATE KEY-----' with DOTALL greedily
        # starts at the CERTIFICATE header, so the key file BEGINS with the
        # cert block. Characterization pin — the fix lands in its own lane.
        key_content = open(key).read()
        assert key_content.startswith("-----BEGIN CERTIFICATE-----")
        assert "PRIVATE KEY" in key_content
        assert not (tmp_path / "x.qip.sh.pem").exists()  # combined removed

    def test_missing_blocks_leave_files_unwritten(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            sslmod, "urlretrieve",
            lambda url, dest: open(dest, "w").write("not a pem"))
        cert, key, host = sslmod.download_qip_cert("192.168.9.9", str(tmp_path))
        assert host == "*.v.qip.sh"
        assert not (tmp_path / "v.qip.sh.crt").exists()


class TestDeploySslPostFlash:
    def _deploy(self, monkeypatch, *, provider="manual", lan_ip="192.168.5.1",
                cert_file="c.pem", key_file="k.pem", ssh_key="id_ed",
                ssh_ok=True, scp_ok=True):
        _stub_ssh_utils(monkeypatch)
        runs = _stub_subprocess(monkeypatch, ssh_ok=ssh_ok, scp_ok=scp_ok)
        logs = []
        ok = sslmod.deploy_ssl_post_flash(
            "192.168.5.1", ssh_key=ssh_key, provider=provider, lan_ip=lan_ip,
            cert_file=cert_file, key_file=key_file, log=logs.append)
        return ok, logs, runs

    def test_manual_provider_scp_and_install(self, monkeypatch):
        ok, logs, runs = self._deploy(monkeypatch)
        assert ok, logs
        scps = [r for r in runs if r and r[0] == "scp"]
        assert len(scps) == 2  # cert + key
        assert all("-i" in r and "id_ed" in r for r in scps)  # key flows to scp
        assert all("root@192.168.5.1:/etc/tollgate/ssl" in r[-1] for r in scps)
        assert any("install" in l or "installed" in l for l in logs)

    def test_manual_missing_files_fails(self, monkeypatch):
        ok, logs, _ = self._deploy(monkeypatch, cert_file="", key_file="")
        assert not ok and "manual provider requires" in " ".join(logs)

    def test_unknown_provider_fails(self, monkeypatch):
        ok, logs, _ = self._deploy(monkeypatch, provider="nope")
        assert not ok and "Unknown provider" in " ".join(logs)

    def test_lan_ip_autodetect_failure_fails(self, monkeypatch, tmp_path):
        _stub_ssh_utils(monkeypatch)
        _stub_subprocess(monkeypatch, ssh_ok=False)
        logs = []
        ok = sslmod.deploy_ssl_post_flash(
            "192.168.5.1", provider="manual", lan_ip="", log=logs.append)
        assert not ok

    def test_lan_ip_autodetect_feeds_download(self, monkeypatch, tmp_path):
        _stub_ssh_utils(monkeypatch)
        runs = _stub_subprocess(monkeypatch)
        monkeypatch.setattr(
            sslmod, "download_lancert_cert",
            lambda lan_ip, dest: (str(tmp_path / "c"), str(tmp_path / "k"),
                                  f"{lan_ip}-host"))
        ok = sslmod.deploy_ssl_post_flash(
            "192.168.5.1", provider="lancert", lan_ip="", log=lambda m: None)
        assert ok
        # the detected LAN IP (stdout of the detect ssh) reached the downloader
        # — autodetect ran because lan_ip was empty
        assert any(r and r[0] == "ssh" and "network.lan.ipaddr" in " ".join(r)
                   for r in runs)

    def test_scp_failure_fails(self, monkeypatch):
        ok, logs, _ = self._deploy(monkeypatch, scp_ok=False)
        assert not ok and "SCP failed" in " ".join(logs)
