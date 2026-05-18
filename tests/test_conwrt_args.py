from __future__ import annotations

import py_compile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_conwrt_script_compiles() -> None:
    py_compile.compile(str(ROOT / "scripts" / "conwrt.py"), doraise=True)


def test_firmware_manager_script_compiles() -> None:
    py_compile.compile(str(ROOT / "scripts" / "firmware-manager.py"), doraise=True)
