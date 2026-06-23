#!/usr/bin/env python3
"""render_markdown — Markdown transport over the Op IR.

Produces human-readable Markdown from the same typed operations that
``render_shell`` turns into a shell script and ``render_ubus`` turns into RPC
calls. Comment ops become section headers; BlankLine ops become paragraph
breaks; every other op is grouped into a fenced ``sh`` block whose contents
are delegated to ``render_shell`` so command text can never drift between the
shell and markdown transports.

For richer, prose-led instructions, the flows layer wraps this with a human
title and explanation per step.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from profile.ops import Op


def render_markdown(ops: "list[Op]") -> str:
    from profile.ops import BlankLine, Comment, render_shell

    out: list[str] = []
    code_buf: list = []

    def flush_code() -> None:
        if not code_buf:
            return
        out.append("```sh")
        out.append(render_shell(code_buf))
        out.append("```")
        out.append("")
        code_buf.clear()

    for op in ops:
        if isinstance(op, Comment):
            flush_code()
            text = op.text.strip().strip("-").strip()
            if text:
                out.append(f"### {text}")
                out.append("")
        elif isinstance(op, BlankLine):
            flush_code()
        else:
            code_buf.append(op)

    flush_code()
    return "\n".join(out).rstrip() + "\n"
