"""Shared pytest configuration.

Disables the soft-deprecation delay for every test run so migrated Python
commands stay fast under test; the notice itself still prints (and its
behavior is covered by tests/test_rust_migration.py).
"""

from __future__ import annotations

import os

os.environ.setdefault("CONWRT_RUST_MIGRATION_DELAY", "0")
