from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from profile.apply import _wait_for_internet


def _mock_run(returncode: int, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def test_wait_for_internet_succeeds_immediately() -> None:
    with patch("profile.apply.time") as mock_time, \
         patch("profile.apply.subprocess.run", return_value=_mock_run(0)):
        mock_time.time.side_effect = [0, 1, 1]
        log = MagicMock()

        assert _wait_for_internet("1.2.3.4", "", log, timeout=60) is True
        log.assert_any_call("  ✓ internet reachable (1s)")


def test_wait_for_internet_retries_then_succeeds() -> None:
    with patch("profile.apply.time") as mock_time, \
         patch("profile.apply.subprocess.run") as mock_run, \
         patch("profile.apply.time.sleep"):
        mock_time.time.side_effect = [0, 10, 20, 20]
        mock_run.side_effect = [_mock_run(1), _mock_run(0)]
        log = MagicMock()

        assert _wait_for_internet("1.2.3.4", "", log, timeout=60) is True


def test_wait_for_internet_timeout() -> None:
    with patch("profile.apply.time") as mock_time, \
         patch("profile.apply.subprocess.run", return_value=_mock_run(1)), \
         patch("profile.apply.time.sleep"):
        mock_time.time.side_effect = [0, 30, 61]
        log = MagicMock()

        assert _wait_for_internet("1.2.3.4", "", log, timeout=60) is False


def test_wait_for_internet_timeout_expired_treated_as_failure() -> None:
    with patch("profile.apply.time") as mock_time, \
         patch("profile.apply.subprocess.run", side_effect=subprocess.TimeoutExpired("ssh", 10)), \
         patch("profile.apply.time.sleep"):
        mock_time.time.side_effect = [0, 10, 61]
        log = MagicMock()

        assert _wait_for_internet("1.2.3.4", "", log, timeout=60) is False


def test_wait_for_internet_oserror_treated_as_failure() -> None:
    with patch("profile.apply.time") as mock_time, \
         patch("profile.apply.subprocess.run", side_effect=OSError("no route")), \
         patch("profile.apply.time.sleep"):
        mock_time.time.side_effect = [0, 10, 61]
        log = MagicMock()

        assert _wait_for_internet("1.2.3.4", "", log, timeout=60) is False
