"""Generate crates/conwrt-core/src/plan/net_roles_bodies.rs from
scripts/use_cases/net_roles.py — byte-exact script constants (the
plan_cellular_bodies.rs pattern: never transcribe by hand).

Run from the conwrt repo root after editing net_roles.py:
  PATH=/usr/bin:/bin:/usr/local/bin python3 scripts/gen_net_roles_bodies.py
"""
import ast
import pathlib
import re

SRC = pathlib.Path("scripts/use_cases/net_roles.py")
OUT = pathlib.Path("crates/conwrt-core/src/plan/net_roles_bodies.rs")

NAMES = [
    ("_MODE_DAEMON", "MODE_DAEMON_SH"),
    ("_MODE_INIT", "MODE_INIT_SH"),
    ("_MODE_HOTPLUG", "MODE_HOTPLUG_SH"),
    ("_MODE_BUTTON", "MODE_BUTTON_SH"),
    ("_CONN_NOOP", "CONN_NOOP_SH"),
    ("_CONN_ADAPTER", "CONN_ADAPTER_SH"),
    ("_CONN_INIT", "CONN_INIT_SH"),
    ("_GUARD_DAEMON", "GUARD_DAEMON_SH"),
    ("_GUARD_INIT", "GUARD_INIT_SH"),
]

src = SRC.read_text()
tree = ast.parse(src)
consts = {}
for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in dict(NAMES):
                # r"""...""" raw strings -> ast gives the exact value
                consts[t.id] = ast.literal_eval(node.value)

missing = [py for py, _ in NAMES if py not in consts]
assert not missing, f"missing constants: {missing}"

def rust_raw_literal(s: str) -> str:
    # r#"..."# handles everything except a literal `"#` sequence
    assert '"#' not in s, "constant contains \"# — needs a longer hash raw string"
    return 'r#"' + s + '"#'

lines = [
    "// GENERATED from scripts/use_cases/net_roles.py by",
    "// scripts/gen_net_roles_bodies.py — DO NOT EDIT BY HAND; byte parity",
    "// with 1.x is asserted by the fixture corpus.",
    "",
]
for py, rs in NAMES:
    body = consts[py]
    lines.append(f"/// 1.x `{py}` (byte-exact).")
    lines.append(f"pub(super) const {rs}: &str = {rust_raw_literal(body)};")
    lines.append("")

OUT.write_text("\n".join(lines))
print(f"wrote {OUT} ({OUT.stat().st_size} bytes, {len(consts)} constants)")
