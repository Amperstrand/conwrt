from __future__ import annotations

from unittest.mock import MagicMock, call, patch

from profile.apply import _scp_install_packages

RELEASE_OUTPUT = (
    "DISTRIB_ID='OpenWrt'\n"
    "DISTRIB_RELEASE='24.10.2'\n"
    "DISTRIB_TARGET='ramips/mt7621'\n"
    "DISTRIB_ARCH='mipsel_24kc'\n"
    "DISTRIB_DESCRIPTION='OpenWrt 24.10.2'\n"
)

PACKAGES_INDEX = (
    "Package: sqm-scripts\n"
    "Version: 1.5.1-1\n"
    "Filename: sqm-scripts_1.5.1-1_all.ipk\n\n"
    "Package: luci-app-sqm\n"
    "Version: 1.5.1-1\n"
    "Filename: luci-app-sqm_1.5.1-1_all.ipk\n\n"
)


def _mock_run(returncode: int, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def test_scp_install_success() -> None:
    log = MagicMock()
    with patch("profile.apply.subprocess.run") as mock_run, \
         patch("profile.apply._download_package_index", return_value=PACKAGES_INDEX), \
         patch("profile.apply.urllib.request.urlretrieve"), \
         patch("profile.apply.shutil.rmtree"), \
         patch("profile.apply.tempfile.mkdtemp", return_value="/tmp/conwrt-scp-test"):

        mock_run.side_effect = [
            _mock_run(0, stdout=RELEASE_OUTPUT),
            _mock_run(0),
            _mock_run(0),
        ]

        result = _scp_install_packages("1.2.3.4", ["sqm-scripts"], "/key", log)

    assert result is True


def test_scp_install_device_query_fails() -> None:
    log = MagicMock()
    with patch("profile.apply.subprocess.run", return_value=_mock_run(1)):
        result = _scp_install_packages("1.2.3.4", ["sqm-scripts"], "", log)

    assert result is False
    log.assert_any_call("  ⚠ scp fallback: cannot read /etc/openwrt_release from device")


def test_scp_install_missing_arch() -> None:
    log = MagicMock()
    bad_output = "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.2'\n"
    with patch("profile.apply.subprocess.run", return_value=_mock_run(0, stdout=bad_output)):
        result = _scp_install_packages("1.2.3.4", ["sqm-scripts"], "", log)

    assert result is False
    log.assert_any_call("  ⚠ scp fallback: missing DISTRIB_RELEASE or DISTRIB_ARCH")


def test_scp_install_index_unavailable() -> None:
    log = MagicMock()
    with patch("profile.apply.subprocess.run", return_value=_mock_run(0, stdout=RELEASE_OUTPUT)), \
         patch("profile.apply._download_package_index", return_value=None), \
         patch("profile.apply.shutil.rmtree"):
        result = _scp_install_packages("1.2.3.4", ["sqm-scripts"], "", log)

    assert result is False


def test_scp_install_package_not_in_index() -> None:
    log = MagicMock()
    with patch("profile.apply.subprocess.run", return_value=_mock_run(0, stdout=RELEASE_OUTPUT)), \
         patch("profile.apply._download_package_index", return_value=PACKAGES_INDEX), \
         patch("profile.apply.shutil.rmtree"):
        result = _scp_install_packages("1.2.3.4", ["nonexistent-pkg"], "", log)

    assert result is False
    log.assert_any_call("  ⚠ scp fallback: nonexistent-pkg not found in package index")


def test_scp_install_download_fails() -> None:
    log = MagicMock()
    import urllib.error
    with patch("profile.apply.subprocess.run", return_value=_mock_run(0, stdout=RELEASE_OUTPUT)), \
         patch("profile.apply._download_package_index", return_value=PACKAGES_INDEX), \
         patch("profile.apply.urllib.request.urlretrieve", side_effect=urllib.error.URLError("net")), \
         patch("profile.apply.shutil.rmtree"):
        result = _scp_install_packages("1.2.3.4", ["sqm-scripts"], "", log)

    assert result is False
    log.assert_any_call("  ⚠ scp fallback: no packages could be downloaded")


def test_scp_install_scp_transfer_fails() -> None:
    log = MagicMock()
    with patch("profile.apply.subprocess.run") as mock_run, \
         patch("profile.apply._download_package_index", return_value=PACKAGES_INDEX), \
         patch("profile.apply.urllib.request.urlretrieve"), \
         patch("profile.apply.shutil.rmtree"), \
         patch("profile.apply.tempfile.mkdtemp", return_value="/tmp/conwrt-scp-test"):

        mock_run.side_effect = [
            _mock_run(0, stdout=RELEASE_OUTPUT),
            _mock_run(1, stderr="Permission denied"),
        ]

        result = _scp_install_packages("1.2.3.4", ["sqm-scripts"], "/key", log)

    assert result is False
    log.assert_any_call("  ⚠ scp fallback: transfer failed: Permission denied")
