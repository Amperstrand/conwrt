"""vm_port — port claiming for VM fixtures on shared multi-agent hosts."""
import socket
from unittest.mock import patch

import pytest

from vm_port import holder_hint, port_bound, port_from_env, require_free


class TestPortFromEnv:
    def test_default_when_unset(self):
        with patch.dict("os.environ", {}, clear=True):
            assert port_from_env("CONWRT_X_PORT", 2222) == 2222

    def test_override(self):
        with patch.dict("os.environ", {"CONWRT_X_PORT": "2322"}):
            assert port_from_env("CONWRT_X_PORT", 2222) == 2322

    def test_rejects_non_numeric(self):
        with patch.dict("os.environ", {"CONWRT_X_PORT": "https"}):
            with pytest.raises(RuntimeError, match="not a port number"):
                port_from_env("CONWRT_X_PORT", 2222)

    def test_rejects_out_of_range(self):
        with patch.dict("os.environ", {"CONWRT_X_PORT": "70000"}):
            with pytest.raises(RuntimeError, match="out of range"):
                port_from_env("CONWRT_X_PORT", 2222)


class TestPortBound:
    def test_bound_port_detected(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]
            assert port_bound(port, "127.0.0.1") is True

    def test_free_port_not_bound(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        assert port_bound(port, "127.0.0.1") is False


class TestRequireFree:
    def test_free_port_passes(self):
        require_free(0, "127.0.0.1", "CONWRT_X_PORT", "test fixture")

    def test_bound_port_names_env_var_and_holder(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]
            with pytest.raises(RuntimeError, match=r"CONWRT_X_PORT=\d+") as exc:
                require_free(port, "127.0.0.1", "CONWRT_X_PORT", "test fixture")
            assert "test fixture" in str(exc.value)
            assert "active-sessions" in str(exc.value)


class TestHolderHint:
    def test_names_the_listener_port(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]
            hint = holder_hint(port)
            assert f":{port}" in hint
