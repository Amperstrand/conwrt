"""Tests for build_ipk.sh — conwrt ipk packaging."""
from __future__ import annotations

import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD_SCRIPT = ROOT / "scripts" / "build_ipk.sh"


def _build_ipk(output_dir: str) -> str:
    result = subprocess.run(
        ["sh", str(BUILD_SCRIPT), "--output", output_dir],
        capture_output=True, text=True, check=True,
    )
    for line in result.stdout.splitlines():
        if line.startswith("==> Built:"):
            return line.split("==> Built:")[1].strip()
    raise RuntimeError(f"Could not find ipk path in output:\n{result.stdout}")


def _extract_ipk(ipk_path: str, extract_dir: str) -> None:
    tmpdir = tempfile.mkdtemp()
    subprocess.run(["ar", "x", ipk_path], cwd=tmpdir, check=True, capture_output=True)

    with open(os.path.join(tmpdir, "debian-binary")) as f:
        assert f.read().strip() == "2.0"

    with tarfile.open(os.path.join(tmpdir, "control.tar.gz"), "r:gz") as tf:
        tf.extractall(os.path.join(extract_dir, "control"))

    with tarfile.open(os.path.join(tmpdir, "data.tar.gz"), "r:gz") as tf:
        tf.extractall(os.path.join(extract_dir, "data"))


class TestBuildIpk(unittest.TestCase):
    def setUp(self) -> None:
        self.output_dir = tempfile.mkdtemp()
        self.extract_dir = tempfile.mkdtemp()

    def test_build_produces_ipk(self) -> None:
        ipk_path = _build_ipk(self.output_dir)
        self.assertTrue(os.path.exists(ipk_path))
        self.assertTrue(ipk_path.endswith("_all.ipk"))

    def test_ipk_naming_has_version(self) -> None:
        ipk_path = _build_ipk(self.output_dir)
        basename = os.path.basename(ipk_path)
        self.assertTrue(basename.startswith("conwrt_"))
        self.assertIn("alpha", basename)
        self.assertTrue(basename.endswith("_all.ipk"))
        parts = basename.replace("_all.ipk", "").split("+")
        self.assertGreaterEqual(len(parts), 2, f"Expected git hash in version: {basename}")

    def test_control_file_valid(self) -> None:
        ipk_path = _build_ipk(self.output_dir)
        _extract_ipk(ipk_path, self.extract_dir)
        control_path = os.path.join(self.extract_dir, "control", "control")
        self.assertTrue(os.path.exists(control_path))
        with open(control_path) as f:
            text = f.read()
        self.assertIn("Package: conwrt", text)
        self.assertIn("Architecture: all", text)
        self.assertIn("python3-base", text)
        self.assertIn("python3-light", text)
        self.assertIn("Version: 0.0.0-alpha", text)

    def test_data_has_conwrt_py(self) -> None:
        ipk_path = _build_ipk(self.output_dir)
        _extract_ipk(ipk_path, self.extract_dir)
        conwrt_py = os.path.join(self.extract_dir, "data", "usr", "share", "conwrt", "conwrt.py")
        self.assertTrue(os.path.exists(conwrt_py))

    def test_data_has_wrapper(self) -> None:
        ipk_path = _build_ipk(self.output_dir)
        _extract_ipk(ipk_path, self.extract_dir)
        wrapper = os.path.join(self.extract_dir, "data", "usr", "bin", "conwrt")
        self.assertTrue(os.path.exists(wrapper))
        with open(wrapper) as f:
            text = f.read()
        self.assertIn("python3", text)
        self.assertIn("/usr/share/conwrt/conwrt.py", text)

    def test_data_has_models(self) -> None:
        ipk_path = _build_ipk(self.output_dir)
        _extract_ipk(ipk_path, self.extract_dir)
        models_dir = os.path.join(self.extract_dir, "data", "etc", "conwrt", "models")
        self.assertTrue(os.path.isdir(models_dir))
        jsons = [f for f in os.listdir(models_dir) if f.endswith(".json")]
        self.assertGreater(len(jsons), 0)

    def test_data_has_subpackages(self) -> None:
        ipk_path = _build_ipk(self.output_dir)
        _extract_ipk(ipk_path, self.extract_dir)
        for pkg in ("flash", "profile", "use_cases"):
            pkg_dir = os.path.join(self.extract_dir, "data", "usr", "share", "conwrt", pkg)
            self.assertTrue(os.path.isdir(pkg_dir), f"Missing sub-package: {pkg}")
            inits = [f for f in os.listdir(pkg_dir) if f.endswith(".py")]
            self.assertGreater(len(inits), 0, f"No .py files in {pkg}")

    def test_data_excludes_dev_scripts(self) -> None:
        ipk_path = _build_ipk(self.output_dir)
        _extract_ipk(ipk_path, self.extract_dir)
        share = os.path.join(self.extract_dir, "data", "usr", "share", "conwrt")
        for skip in ("validate_models.py", "generate_matrix.py", "dlink_sge_sign.py"):
            self.assertFalse(
                os.path.exists(os.path.join(share, skip)),
                f"Dev script should be excluded: {skip}",
            )

    def test_ipk_size_reasonable(self) -> None:
        ipk_path = _build_ipk(self.output_dir)
        size_kb = os.path.getsize(ipk_path) // 1024
        self.assertLess(size_kb, 500, f"ipk too large: {size_kb}KB")
        self.assertGreater(size_kb, 50, f"ipk suspiciously small: {size_kb}KB")

    def test_postinst_exists(self) -> None:
        ipk_path = _build_ipk(self.output_dir)
        _extract_ipk(ipk_path, self.extract_dir)
        postinst = os.path.join(self.extract_dir, "control", "postinst")
        self.assertTrue(os.path.exists(postinst))


class TestConwrtVersion(unittest.TestCase):
    def test_version_flag(self) -> None:
        result = subprocess.run(
            ["python3", str(ROOT / "scripts" / "conwrt.py"), "--version"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("conwrt", result.stdout)
        self.assertIn("0.0.0", result.stdout)

    def test_version_importable(self) -> None:
        import importlib
        spec = importlib.util.spec_from_file_location("conwrt", str(ROOT / "scripts" / "conwrt.py"))
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        sys_modules_key = "conwrt_test_version"
        import sys
        sys.modules[sys_modules_key] = mod
        spec.loader.exec_module(mod)
        self.assertIsInstance(mod.__version__, str)
        self.assertTrue(mod.__version__.startswith("0.0.0"))


if __name__ == "__main__":
    unittest.main()
