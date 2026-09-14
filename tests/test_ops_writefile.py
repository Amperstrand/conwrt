"""Tests for the WriteFile operation (profile/ops.py)."""
from __future__ import annotations

import pytest

from profile.ops import WriteFile, render_shell, render_ubus, render_writefile


class TestWriteFileDataclass:
    def test_defaults(self):
        op = WriteFile(path="/etc/openvpn/pia-auth.txt", content="user\npass\n")
        assert op.path == "/etc/openvpn/pia-auth.txt"
        assert op.mode == "600"

    def test_custom_mode(self):
        op = WriteFile(path="/usr/bin/pia-health", content="#!/bin/sh\n", mode="755")
        assert op.mode == "755"


class TestRenderWriteFile:
    def test_heredoc_and_chmod(self):
        rendered = render_writefile(WriteFile(path="/tmp/x", content="hello\n"))
        assert rendered == "cat > '/tmp/x' <<'OPENWRT_EOF'\nhello\nOPENWRT_EOF\nchmod 600 /tmp/x"

    def test_trailing_newline_added(self):
        rendered = render_writefile(WriteFile(path="/tmp/x", content="no-newline"))
        assert "no-newline\nOPENWRT_EOF" in rendered

    def test_mode_in_output(self):
        rendered = render_writefile(WriteFile(path="/tmp/x", content="a\n", mode="755"))
        assert rendered.endswith("chmod 755 /tmp/x")

    def test_delimiter_collision_is_escaped(self):
        content = "line\nOPENWRT_EOF\nmore\n"
        rendered = render_writefile(WriteFile(path="/tmp/x", content=content))
        # A different delimiter must be chosen so the body can't terminate early.
        assert "<<'OPENWRT_EOF_1'" in rendered
        assert "\nOPENWRT_EOF_1\n" in rendered

    def test_single_quote_in_path_is_rejected(self):
        with pytest.raises(ValueError, match="unsafe"):
            render_writefile(WriteFile(path="/tmp/a'b", content="x\n"))

    def test_relative_path_is_rejected(self):
        with pytest.raises(ValueError, match="absolute"):
            render_writefile(WriteFile(path="relative/path", content="x\n"))

    def test_bad_mode_is_rejected(self):
        with pytest.raises(ValueError, match="octal"):
            render_writefile(WriteFile(path="/tmp/x", content="x\n", mode="u+rwx"))


class TestWriteFileInRenderers:
    def test_render_shell_embeds_writefile(self):
        ops = [WriteFile(path="/etc/openvpn/pia.ovpn", content="client\n")]
        rendered = render_shell(ops)
        assert "cat > '/etc/openvpn/pia.ovpn' <<'OPENWRT_EOF'" in rendered
        assert rendered.endswith("chmod 600 /etc/openvpn/pia.ovpn")

    def test_render_ubus_maps_to_exec_fallback(self):
        calls = render_ubus([WriteFile(path="/etc/x", content="y\n")])
        assert len(calls) == 1
        assert calls[0].object_name == "exec"
        assert calls[0].params["fallback"] is True
        assert "cat > '/etc/x'" in calls[0].params["command"]
