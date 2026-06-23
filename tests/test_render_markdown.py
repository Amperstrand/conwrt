"""Characterization tests for the Markdown transport.

The drift-killer invariant: the fenced shell block inside the Markdown must be
byte-identical to ``render_shell`` of the same command ops. Everything else is
structural (Comment → header, BlankLine → section split).
"""
from __future__ import annotations

from profile.ops import (
    BlankLine,
    Comment,
    ServiceAction,
    ShellCommand,
    UciCommit,
    UciSet,
    render_shell,
)
from profile.render_markdown import render_markdown


def test_comment_becomes_header_with_dashes_stripped():
    md = render_markdown([Comment(text="--- WiFi uplink ---")])
    assert "### WiFi uplink" in md


def test_ops_grouped_into_fenced_shell_block_matching_render_shell():
    ops = [
        Comment("Setup"),
        UciSet(config="wireless", section="radio0", values={"disabled": "0"}),
        UciCommit(config="wireless"),
    ]
    md = render_markdown(ops)
    assert "```sh" in md
    expected_block = render_shell(ops[1:])
    assert expected_block in md


def test_service_action_and_shell_command_land_in_the_block():
    ops = [
        ServiceAction(name="nodogsplash", action="restart"),
        ShellCommand(command="wifi reload"),
    ]
    md = render_markdown(ops)
    assert "/etc/init.d/nodogsplash restart" in md
    assert "wifi reload" in md


def test_blank_line_splits_into_separate_fenced_blocks():
    ops = [
        Comment("A"),
        UciCommit(config="wireless"),
        BlankLine(),
        Comment("B"),
        UciCommit(config="network"),
    ]
    md = render_markdown(ops)
    assert md.count("```sh") == 2
    assert "### A" in md and "### B" in md


def test_empty_and_comment_only_ops_produce_no_code_fence():
    md = render_markdown([Comment("only prose"), BlankLine()])
    assert "```sh" not in md
    assert "### only prose" in md


def test_drift_parity_with_tollgate_ops():
    from use_cases.tollgate import _build_tollgate_ops

    ops = _build_tollgate_ops({
        "gateway_name": "net4sats",
        "clientid": "mac",
        "install_hotplug": True,
        "hotplug_interface": "wwan",
    })
    md = render_markdown(ops)
    runs: list[list] = []
    current: list = []
    for op in ops:
        if isinstance(op, (Comment, BlankLine)):
            if current:
                runs.append(current)
                current = []
        else:
            current.append(op)
    if current:
        runs.append(current)

    assert runs, "expected at least one command run"
    for run in runs:
        assert render_shell(run) in md, f"run missing from markdown: {render_shell(run)[:80]}"
