"""Cross-implementation plan-renderer parity harness (Python half).

conwrt has two plan-op implementations:

  - Python 1.x: ``scripts/use_cases/*`` → ``profile.ops.render_shell``
    (complete, all ~30 presets)
  - Rust: ``crates/conwrt-core`` plan/profile pipeline → ``plan::render_shell``
    (the direction the project is going)

Nothing proved the two produce the same shell/uci semantics for the same
use case — this harness does. Each fixture in ``tests/fixtures/parity/`` is
rendered through BOTH implementations and the outputs are normalized and
diffed:

  - Python side: the registered use case's ``build_configure_ops(params)``
    → ``render_shell``.
  - Rust side: the ``conwrt-plan-render`` binary (built once per session)
    renders the same fixture file through the Rust planner.

Normalization (applied identically to both sides):
  1. drop shebang, ``set -e``, blank lines and comment lines
     (presentation-only; the Rust renderer adds a header and per-op
     annotation comments),
  2. tokenize each remaining line with ``shlex.split`` (recovers the exact
     argv the shell would see — quoting differences like
     ``uci set network.'wg0'='interface'`` vs ``uci set network.wg0=interface``
     normalize away),
  3. drop known-equivalent executor decorations: ``2>/dev/null`` words,
     the ``-q`` flag directly after ``uci``, and a trailing ``|| true``
     pair.

The expected status (EQUAL / GAP + reasons) is recorded in
``tests/fixtures/parity/manifest.json`` and asserted: if parity changes in
EITHER direction — a gap closes or a regression opens — the test fails
until the manifest is updated in review. The gap list must shrink, never
silently change. ``scripts/update_parity_golden.py`` regenerates the
Python goldens that pin the Rust side in ``cargo test``.
"""
from __future__ import annotations

import difflib
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from profile.ops import render_shell

import use_cases

REPO = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO / "tests" / "fixtures" / "parity"

# Words that are executor-side decorations with no semantic effect for
# parity: stderr silencing, uci quiet flag, and a trailing `|| true`
# guard (present in both renderers in various spots).
_DROP_WORDS = {"2>/dev/null"}

# 2.x-only package-install preamble (EnsurePackage apk/opkg blocks) — a
# deliberate Rust-side extension; 1.x Python bakes packages into the
# image, so its configure render carries no install lines. Same
# exclusion as crates/conwrt-core/src/parity.rs::command_lines and
# tests/use_case_goldens.rs. The `if ! (opkg list-installed` shape is the
# same preamble wrapped in an idempotence guard (ssl's libustream).
_DROP_LINE_PREFIXES = (
    "opkg install ",
    "if command -v apk ",
    "&& apk add ",
    "if ! (opkg list-installed ",
    'if [ -n "$(opkg list-installed ',
    # 1.x mptcp-bonding renders its EnsurePackage as a single best-effort
    # line — same semantic as the 2.x preamble above, so both drop.
    "apk add curl 2>/dev/null",
)


def _normalize_line(line: str) -> list[str] | None:
    stripped = line.strip()
    # 2.x runs under a `set -e` preamble (itself dropped above) and so
    # guards best-effort substitutions with `|| true` — the 1.x render
    # is bare. Strip the shim inside `$( ... )` before tokenizing (the
    # token-level `|| true` drop below cannot see it: the closing paren
    # glues to the word).
    stripped = stripped.replace(" || true)", ")")
    if not stripped or stripped.startswith("#"):
        return None
    if stripped == "set -e" or stripped.startswith("#!"):
        return None
    if stripped.startswith(_DROP_LINE_PREFIXES):
        return None
    try:
        tokens = shlex.split(stripped)
    except ValueError as err:  # unbalanced quoting — a real problem
        raise AssertionError(f"cannot tokenize {stripped!r}: {err}") from err
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _DROP_WORDS:
            i += 1
            continue
        # `uci -q …` → `uci …` (quiet flag only, directly after `uci`)
        if tok == "-q" and out and out[-1] == "uci":
            i += 1
            continue
        # trailing `|| true` guard
        if tok == "||" and i + 1 < len(tokens) and tokens[i + 1] == "true":
            i += 2
            continue
        out.append(tok)
        i += 1
    return out


def normalize(script: str) -> list[list[str]]:
    """Normalize a rendered script to its semantic command stream."""
    # Join backslash-continued lines FIRST: a trailing `\\` is shell
    # line-wrapping (presentation), not a semantic boundary — tokenizing
    # the wrapped halves separately chokes on the dangling escape. Applied
    # to both renders identically. Heredoc BODIES are data, not command
    # lines (shlex chokes on awk/sed quoting inside them): each body is
    # emitted as one two-token opaque comparison unit, bypassing _normalize_line.
    raw = script.splitlines()
    out: list[list[str]] = []
    buf = ""
    heredoc_marker: str | None = None
    heredoc_lines: list[str] = []
    for line in raw:
        if heredoc_marker is not None:
            if line.strip() == heredoc_marker:
                out.append(["__HEREDOC__", "\n".join(heredoc_lines)])
                heredoc_marker = None
                heredoc_lines = []
            else:
                heredoc_lines.append(line.rstrip())
            continue
        candidate = (buf + line) if buf else line
        if _opens_shell_continuation(candidate):
            # either a trailing backslash (line wrap) or an unterminated
            # single quote (a printf-embedded script — legal multi-line
            # shell); both are presentation joins, not command boundaries.
            # A backslash-newline inside the quoted literal (1.x's
            # render_shell line-wrap) is equivalent to the clean newline
            # the Rust renderer emits — normalize both to a plain newline.
            stripped_c = candidate.rstrip()
            if stripped_c.endswith("\\"):
                buf = stripped_c[:-1] + " "
            else:
                buf = candidate.replace("\\\n", "\n") + "\n"
            continue
        line = candidate
        buf = ""
        if (tok := _normalize_line(line)) is not None:
            out.append(tok)
        start = _heredoc_start(line)
        if start is not None:
            heredoc_marker = start
    if buf:  # trailing continuation with nothing after it
        if (tok := _normalize_line(buf.rstrip())) is not None:
            out.append(tok)
    return out


def _opens_shell_continuation(candidate: str) -> bool:
    """True when the shell would keep reading: trailing `\\`, or an odd
    number of unescaped single quotes (multi-line quoted literal)."""
    stripped = candidate.rstrip()
    if stripped.endswith("\\"):
        return True
    return stripped.count("'") % 2 == 1


def _heredoc_start(line: str) -> str | None:
    """Return the terminator if `line` opens a heredoc (`<< 'EOF'` etc.)."""
    import re

    m = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
    return m.group(1) if m else None


def _render_tokens(lines: list[list[str]]) -> list[str]:
    return [" ".join(t) for t in lines]


def _resolve_target_dir(cargo: str, repo: Path) -> Path:
    """The EFFECTIVE cargo target directory (#432): the host's global
    ~/.cargo/config.toml can pin build.target-dir (disk consolidation,
    2026-10-19), which silently redirects builds away from the repo's
    ./target while this harness kept looking there — 6 wireguard_server
    parity cases ERRORed locally with 'missing after cargo build' while
    CI (no redirect) stayed green. cargo metadata reports the effective
    directory (config + env + defaults), so ask the source of truth
    instead of reconstructing the rules."""
    proc = subprocess.run(
        [cargo, "metadata", "--format-version", "1", "--no-deps"],
        cwd=repo, capture_output=True, text=True, timeout=60,
    )
    if proc.returncode == 0:
        try:
            return Path(json.loads(proc.stdout)["target_directory"])
        except (json.JSONDecodeError, KeyError):
            pass
    # metadata unavailable (exotic toolchain): fall back to the old
    # env-or-repo guess rather than failing the whole session
    return Path(os.environ.get("CARGO_TARGET_DIR", str(repo / "target")))


@pytest.fixture(scope="session")
def plan_render_bin() -> Path:
    cargo = shutil.which("cargo")
    if cargo is None:
        pytest.skip("cargo toolchain not available for the Rust parity renderer")
    target_dir = _resolve_target_dir(cargo, REPO)
    bin_path = target_dir / "debug" / "conwrt-plan-render"
    if not bin_path.exists():
        build = subprocess.run(
            [cargo, "build", "-q", "-p", "conwrt-cli", "--bin", "conwrt-plan-render"],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            # check=True used to raise CalledProcessError with the reason
            # swallowed — the 2026-10-22 runner rustup failures (#439/#443)
            # cost a debug round purely to recover this stderr.
            pytest.fail(
                f"conwrt-plan-render build failed (exit {build.returncode}):\n"
                f"{build.stderr.strip()}"
            )
    assert bin_path.exists(), f"{bin_path} missing after cargo build"
    # #432 consequence 2: a stale-but-present binary (shared global
    # target dir, built by an older checkout) produced false 'no Rust
    # profile' reds. The binary carries its build HEAD; mismatch with
    # the live HEAD = rebuild once and re-verify.
    _rebuild_if_stale(cargo, bin_path)
    return bin_path


def _current_head(repo: Path) -> str:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                          capture_output=True, text=True, timeout=30)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _rebuild_if_stale(cargo: str, bin_path: Path) -> None:
    import subprocess as sp
    stamp_proc = sp.run([str(bin_path), "--stamp"], capture_output=True, text=True, timeout=60)
    stamp = stamp_proc.stdout.strip()
    if stamp == "unknown":
        return  # hermetic no-git build: stamped, trusted as-is
    head = _current_head(REPO)
    if not head:
        return  # no git context to compare against
    if not stamp:
        # PRE-STAMP binary (built before the flag existed): unverifiable,
        # and the shared-cache hazard class itself — rebuild.
        print("parity render bin predates --stamp (unverifiable) — rebuilding")
    elif stamp != head:
        print(f"parity render bin is stale (built {stamp[:12]}, HEAD {head[:12]}) — rebuilding")
    else:
        return
    # cargo does not rerun build scripts when only HEAD moved (it caches on
    # rerun-if-changed inputs = build.rs itself): touch build.rs so the
    # stamp refreshes, otherwise the rebuild would re-emit the OLD stamp
    # and the guard would false-fail on its own post-check.
    build_rs = REPO / "apps" / "conwrt-cli" / "build.rs"
    try:
        import time as _t
        build_rs.touch(exist_ok=True)
    except OSError:
        pass
    build = sp.run([cargo, "build", "-q", "-p", "conwrt-cli", "--bin", "conwrt-plan-render"],
                   cwd=REPO, capture_output=True, text=True, timeout=600)
    if build.returncode != 0:
        pytest.fail(f"stale render bin rebuild failed: {build.stderr.strip()[:400]}")
    stamp2 = sp.run([str(bin_path), "--stamp"], capture_output=True, text=True, timeout=60).stdout.strip()
    if stamp2 not in (head, "unknown"):
        pytest.fail(
            f"render bin still stale after rebuild: built {stamp2[:12]}, HEAD {head[:12]} "
            f"(shared target dir thrash?)"
        )


def _load_manifest() -> dict:
    return json.loads((FIXTURE_DIR / "manifest.json").read_text())


def _fixtures() -> list[dict]:
    manifest = _load_manifest()
    out = []
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        if path.name == "manifest.json":
            continue
        entry = manifest["fixtures"].get(path.stem)
        out.append(
            {
                "stem": path.stem,
                "path": path,
                "fixture": json.loads(path.read_text()),
                "expect": entry["expect"] if entry else None,
                "entry": entry,
            }
        )
    return out


def _python_render(fixture: dict) -> str:
    uc = use_cases.get(fixture["use_case"])
    assert uc is not None, f"use case {fixture['use_case']} not registered"
    # String-script builders (firstboot-class use cases like
    # maas-portable-lab) carry build_configure returning the script
    # directly — no ops builder exists by design (#768: plan-side-only).
    if uc.build_configure_ops is None:
        assert uc.build_configure is not None, (
            f"use case {fixture['use_case']} has neither ops nor script builder"
        )
        return uc.build_configure(fixture["params"])
    # Credless vpn-provider rendering: the provider presets fetch
    # credentials / resolve servers over the network at BUILD time. The
    # canonical offline recipe (same values as the Rust-side
    # tests/use_case_goldens.rs regeneration header) stubs those two
    # module functions — parity fixtures must never touch a live API.
    stubs = _VPN_PROVIDER_STUBS.get(fixture["use_case"])
    if stubs:
        return stubs(uc, fixture["params"])
    return render_shell(uc.build_configure_ops(fixture["params"]))


def _make_vpn_stub(module_name: str):
    import importlib

    def _stub(uc, params):
        mod = importlib.import_module(f"use_cases.vpn_providers.{module_name}")
        saved = {n: getattr(mod, n, None) for n in ("_fetch_credentials", "_resolve_server", "_resolve_endpoint")}
        mod._fetch_credentials = lambda basic: {"username": "svcuser1234", "password": "svcpass5678abcd",
                                              "nordlynx_private_key": "STUBPRIVKEYbase64filledfortestonly0000=",
                                              "nordlynx_public_key": "STUBPUBKEYbase64filledfortestonly0000="}
        mod._resolve_server = lambda value, token, tech: {"station": "193.29.107.10", "hostname": "de500.nordvpn.com"}
        mod._resolve_endpoint = lambda value, token, tech="wireguard_udp": ("de500.nordvpn.com", "51820", "STUBPUBKEYbase64filledfortestonly0000=")
        try:
            return render_shell(uc.build_configure_ops(params))
        finally:
            for n, v in saved.items():
                if v is not None:
                    setattr(mod, n, v)

    return _stub


_VPN_PROVIDER_STUBS = {
    "vpn-nordvpn": _make_vpn_stub("nordvpn"),
    "vpn-nordvpn-openvpn": _make_vpn_stub("nordvpn"),
    "vpn-nordvpn-ikev2": _make_vpn_stub("nordvpn"),
}


NO_RUST_ARM_MARKER = "no Rust Profile arm"


def _rust_render(bin_path: Path, fixture_path: Path,
                 *, allow_missing_arm: bool = False) -> str | None:
    proc = subprocess.run(
        [str(bin_path), str(fixture_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        # A fixture whose manifest entry documents the no-Rust-arm GAP may
        # legitimately fail here (the renderer has no Profile for the use
        # case); every OTHER failure stays a hard assert — the gate must
        # not learn to swallow real render errors.
        if allow_missing_arm:
            return None
        raise AssertionError(
            f"Rust renderer failed for {fixture_path.name}: {proc.stderr}"
        )
    return proc.stdout


class TestParityManifest:
    def test_every_fixture_is_recorded(self):
        manifest = _load_manifest()
        files = {p.stem for p in FIXTURE_DIR.glob("*.json")} - {"manifest"}
        recorded = set(manifest["fixtures"])
        assert files == recorded, (
            f"parity manifest out of sync — files: {sorted(files)}, "
            f"recorded: {sorted(recorded)}"
        )

    def test_every_entry_has_valid_expectation(self):
        manifest = _load_manifest()
        for stem, entry in manifest["fixtures"].items():
            assert entry.get("expect") in {"EQUAL", "GAP"}, stem
            if entry["expect"] == "GAP":
                assert entry.get("gap_reasons"), f"{stem}: GAP needs reasons"
                fixture = json.loads((FIXTURE_DIR / f"{stem}.json").read_text())
                assert fixture["use_case"] == entry["use_case"]


class TestPlanRendererParity:
    @pytest.mark.parametrize("fx", _fixtures(), ids=lambda fx: fx["stem"])
    def test_matches_recorded_parity_status(self, plan_render_bin, fx):
        assert fx["expect"] is not None, (
            f"{fx['stem']} missing from manifest.json — record EQUAL or GAP"
        )
        def _safe_norm(script: str):
            # GAP-class fixtures embed multi-KB daemon scripts in single
            # printf lines whose awk '\''-idiom quoting shlex cannot
            # tokenize (tollgate-cellular / net-roles conn-adapter class).
            # A tokenize failure on EITHER side is a GAP, never a crash —
            # the recorded status still gates (gaps close loudly).
            try:
                return normalize(script), None
            except AssertionError as err:
                return None, str(err)[:120]

        py_script = _python_render(fx["fixture"])
        py, py_err = _safe_norm(py_script)
        documented_no_arm = any(NO_RUST_ARM_MARKER in r
                                for r in (fx["entry"] or {}).get("gap_reasons") or [])
        rs_script = _rust_render(plan_render_bin, fx["path"],
                                 allow_missing_arm=documented_no_arm)
        if rs_script is None:
            # recorded GAP with the no-arm reason: the Rust renderer
            # refusing the use case IS the recorded parity status
            assert fx["expect"] == "GAP", (
                f"{fx['stem']}: Rust renderer has no arm but manifest says EQUAL"
            )
            return
        rs, rs_err = _safe_norm(rs_script)
        if py_err or rs_err:
            actual = "GAP"
            detail = f"(normalizer cannot tokenize: {py_err or rs_err})"
        else:
            actual = "EQUAL" if py == rs else "GAP"
            detail = ""
        if actual == "GAP" and detail == "":
            detail = "\n".join(
                difflib.unified_diff(
                    _render_tokens(py),
                    _render_tokens(rs),
                    fromfile=f"python/{fx['stem']}",
                    tofile=f"rust/{fx['stem']}",
                    lineterm="",
                )
            )
        assert actual == fx["expect"], (
            f"{fx['stem']}: parity status changed from "
            f"{fx['expect']} to {actual} — update "
            f"tests/fixtures/parity/manifest.json (gaps close loudly, "
            f"never silently).\n{detail}"
        )

    @pytest.mark.parametrize("fx", _fixtures(), ids=lambda fx: fx["stem"])
    def test_golden_matches_python_render(self, fx):
        golden = FIXTURE_DIR / "golden" / f"{fx['stem']}.sh"
        assert golden.exists(), (
            f"{golden.name} missing — run scripts/update_parity_golden.py"
        )
        assert golden.read_text() == _python_render(fx["fixture"]), (
            f"{fx['stem']}: golden out of date — run scripts/update_parity_golden.py"
        )


class TestTargetDirResolution:
    """#432: the render-bin path must follow the EFFECTIVE cargo target
    dir (config pins, env overrides), not a hardcoded ./target guess."""

    def _fake_cargo(self, tmp_path: Path, target_dir: str) -> str:
        shim = tmp_path / "cargo"
        shim.write_text(
            "#!/bin/sh\n"
            'printf \'{"target_directory": "%s"}\' "' + target_dir + '"\n'
            'case "$1" in metadata) exit 0;; esac\n exit 1\n'
        )
        shim.chmod(0o755)
        return str(shim)

    def test_metadata_target_dir_is_used(self, tmp_path):
        from test_parity_rust_plan import _resolve_target_dir
        cargo = self._fake_cargo(tmp_path, "/opt/shared-target")
        assert _resolve_target_dir(cargo, REPO) == Path("/opt/shared-target")

    def test_broken_metadata_falls_back_to_env_or_repo(self, tmp_path, monkeypatch):
        from test_parity_rust_plan import _resolve_target_dir
        bad = tmp_path / "cargo"
        bad.write_text("#!/bin/sh\nexit 1\n")
        bad.chmod(0o755)
        monkeypatch.setenv("CARGO_TARGET_DIR", "/tmp/env-target")
        assert _resolve_target_dir(str(bad), REPO) == Path("/tmp/env-target")
        monkeypatch.delenv("CARGO_TARGET_DIR")
        assert _resolve_target_dir(str(bad), REPO) == REPO / "target"


class TestRenderBinStampGuard:
    """#432 consequence 2: unverifiable/stale render binaries rebuild."""

    def _shim(self, path, body, chmod=0o755):
        path.write_text(body)
        path.chmod(chmod)

    def test_matching_stamp_does_not_rebuild(self, tmp_path, monkeypatch):
        from test_parity_rust_plan import _rebuild_if_stale, _current_head
        head = _current_head(REPO)
        assert head  # requires git context
        bin_shim = tmp_path / "render-bin"
        self._shim(bin_shim, f"#!/bin/sh\necho {head}\n")
        boom = tmp_path / "cargo"
        self._shim(boom, "#!/bin/sh\necho 'cargo must not run' >&2\nexit 9\n")
        monkeypatch.setattr("shutil.which", lambda n: str(boom))
        # must not raise and must not invoke cargo
        _rebuild_if_stale(str(boom), bin_shim)

    def test_unknown_stamp_skips_rebuild(self, tmp_path, monkeypatch):
        from test_parity_rust_plan import _rebuild_if_stale
        bin_shim = tmp_path / "render-bin"
        self._shim(bin_shim, "#!/bin/sh\necho unknown\n")
        boom = tmp_path / "cargo"
        self._shim(boom, "#!/bin/sh\nexit 9\n")
        _rebuild_if_stale(str(boom), bin_shim)

    def test_stale_stamp_rebuilds_until_current(self, tmp_path, monkeypatch):
        import subprocess as sp
        from test_parity_rust_plan import _rebuild_if_stale, _current_head
        head = _current_head(REPO)
        assert head
        bin_shim = tmp_path / "render-bin"
        # first --stamp prints stale; the fake cargo REWRITES the shim
        # to the current head (simulating the rebuild)
        self._shim(bin_shim, "#!/bin/sh\necho 0000000000000000000000000000000000000000\n")
        cargo = tmp_path / "cargo"
        self._shim(
            cargo,
            "#!/bin/sh\n"
            f"printf '#!/bin/sh\\necho {head}\\n' > {bin_shim}\n"
            f"chmod +x {bin_shim}\nexit 0\n",
        )
        _rebuild_if_stale(str(cargo), bin_shim)
        # the rebuild actually flipped the shim's stamp
        now = sp.run([str(bin_shim)], capture_output=True, text=True).stdout.strip()
        assert now == head
