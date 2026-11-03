from __future__ import annotations

import gzip
from unittest.mock import MagicMock, patch

from profile.apply import _download_package_index, _parse_package_filenames


SAMPLE_INDEX = """\
Package: sqm-scripts
Version: 1.5.1-1
Depends: libc, libubus
Filename: sqm-scripts_1.5.1-1_all.ipk
SHA256sum: abc123

Package: luci-app-sqm
Version: 1.5.1-1
Depends: libc, sqm-scripts
Filename: luci-app-sqm_1.5.1-1_all.ipk

Package: https-dns-proxy
Version: 2023.1-1
Depends: libc, libcares
Filename: https-dns-proxy_2023.1-1_aarch64_cortex-a53.ipk
"""


def test_parse_package_filenames_basic() -> None:
    result = _parse_package_filenames(SAMPLE_INDEX)
    assert result == {
        "sqm-scripts": "sqm-scripts_1.5.1-1_all.ipk",
        "luci-app-sqm": "luci-app-sqm_1.5.1-1_all.ipk",
        "https-dns-proxy": "https-dns-proxy_2023.1-1_aarch64_cortex-a53.ipk",
    }


def test_parse_package_filenames_empty() -> None:
    assert _parse_package_filenames("") == {}


def test_parse_package_filenames_package_without_filename() -> None:
    index = "Package: orphan\nVersion: 1.0\n\nPackage: ok\nFilename: ok_1.0.ipk\n"
    result = _parse_package_filenames(index)
    assert result == {"ok": "ok_1.0.ipk"}


def test_parse_package_filenames_duplicate_package_keeps_last() -> None:
    index = "Package: foo\nFilename: foo_1.0.ipk\n\nPackage: foo\nFilename: foo_2.0.ipk\n"
    result = _parse_package_filenames(index)
    assert result["foo"] == "foo_2.0.ipk"


def test_download_package_index_gzip() -> None:
    compressed = gzip.compress(SAMPLE_INDEX.encode("utf-8"))
    mock_response = MagicMock()
    mock_response.read.return_value = compressed

    with patch("profile.apply.urllib.request.urlopen", return_value=mock_response):
        result = _download_package_index("https://example.com/packages", log=MagicMock())

    assert result is not None
    assert "sqm-scripts" in result


def test_download_package_index_plain_fallback() -> None:
    mock_response = MagicMock()
    mock_response.read.return_value = SAMPLE_INDEX.encode("utf-8")
    call_count = 0

    def fake_urlopen(url, timeout=30):
        nonlocal call_count
        call_count += 1
        if "Packages.gz" in url:
            raise OSError("not found")
        return mock_response

    with patch("profile.apply.urllib.request.urlopen", side_effect=fake_urlopen):
        result = _download_package_index("https://example.com/packages", log=MagicMock())

    assert result is not None
    assert call_count == 2
    assert "sqm-scripts" in result


def test_download_package_index_both_fail() -> None:
    log = MagicMock()
    with patch("profile.apply.urllib.request.urlopen", side_effect=OSError("nope")):
        result = _download_package_index("https://example.com/packages", log=log)

    assert result is None
    assert any("cannot download package index" in str(c) for c in log.call_args_list)


def test_scp_transfer_uses_the_resolved_port(monkeypatch, tmp_path) -> None:
    """The scp fallback must honor CONWRT_SSH_PORT (Codex P2 on #186):
    the raw scp invocation always tried port 22 while the SSH probes
    used `configure --port`'s forwarded port."""
    from profile import apply as apply_mod

    captured: dict[str, list[str]] = {}

    def fake_run(cmd, **kwargs):
        rc = type("RC", (), {"returncode": 0, "stderr": ""})
        if cmd[0] == "ssh":
            # release probe: shape /etc/openwrt_release output
            rc.stdout = "DISTRIB_RELEASE='24.10.8'\nDISTRIB_ARCH='aarch64_cortex-a53'\n"
        else:
            captured["cmd"] = cmd
            rc.stdout = ""
        return rc()

    monkeypatch.setattr(apply_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(apply_mod, "_download_package_index",
                        lambda base, log: "Package: pkg\nFilename: pkg.ipk\n")
    monkeypatch.setattr(apply_mod.urllib.request, "urlretrieve",
                        lambda url, path: None)
    monkeypatch.setenv("CONWRT_SSH_PORT", "2222")

    ok = apply_mod._scp_install_packages("192.168.1.1", ["pkg"], None,
                                         lambda *a: None)
    assert ok
    cmd = captured["cmd"]
    assert cmd[0] == "scp"
    assert "-P" in cmd and cmd[cmd.index("-P") + 1] == "2222"
