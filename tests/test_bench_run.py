"""Hardware-free checks for bench_run — argv injection and manifest."""

from __future__ import annotations

import json
from pathlib import Path

import bench_run as br


def test_build_argv_injects_the_aparcar_trio(tmp_path: Path) -> None:
    argv = br.build_argv(["tests/foo.py"], tmp_path)
    joined = " ".join(argv)
    assert "--lg-log" in joined and str(tmp_path) in joined
    assert "--junitxml" in joined and "report.xml" in joined
    assert "--log-cli-level=CONSOLE" in joined


def test_build_argv_respects_explicit_flags(tmp_path: Path) -> None:
    argv = br.build_argv(
        ["t.py", "--lg-log", "elsewhere", "--junitxml", "x.xml",
         "--log-cli-level=INFO"], tmp_path)
    assert str(tmp_path) not in " ".join(argv)
    assert "CONSOLE" not in " ".join(argv)


def test_run_writes_manifest_and_log(tmp_path: Path) -> None:
    def fake_spawn(argv: list[str], out_dir: Path) -> int:
        (out_dir / "console_main").write_text("boot noise\n")
        (out_dir / "pytest.log").write_text("... 1 passed\n")
        return 0

    manifest = br.run("unit", ["tests/fake.py"], device_host="h",
                      runs_dir=tmp_path, boot_prober=lambda h: "boot-xyz",
                      spawn=fake_spawn)
    assert manifest["rc"] == 0 and manifest["boot_id"] == "boot-xyz"
    assert manifest["device"] == "h" and manifest["run_id"].endswith("-unit")
    assert "manifest.json" in manifest["evidence"]
    on_disk = json.loads((tmp_path / manifest["run_id"] / "manifest.json").read_text())
    assert on_disk["run_id"] == manifest["run_id"]


def test_run_without_host_leaves_boot_id_empty(tmp_path: Path) -> None:
    manifest = br.run("vm", ["t.py"], device_host="", runs_dir=tmp_path,
                      boot_prober=lambda h: "should-not-be-called")
    assert manifest["boot_id"] == "" and manifest["device"] == ""
