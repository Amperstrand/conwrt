"""Tests for scripts/validate_models.py — model JSON validation.

Covers the schema + ad-hoc checks performed by ``validate_models.main()``:

  * filename stem must equal ``id``
  * ``openwrt.profile`` must be present (FAIL)
  * ``openwrt.device`` should be present (WARN-only, does not fail)
  * jsonschema errors are reported with dotted path or ``<root>``
  * ``flash_methods`` without matching ``tested_hardware`` entries print a note

Tests run against the real repo schema (``schemas/model.schema.json``) copied
into a temp dir so the production schema is exercised end-to-end.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import validate_models  # noqa: E402

REAL_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent / "schemas" / "model.schema.json"
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _valid_model(model_id: str) -> dict:
    """Return a deepcopy-safe model dict that passes the schema and main()."""
    return {
        "id": model_id,
        "vendor": "TestCorp",
        "description": "Test device for unit tests",
        "openwrt": {
            "target": "testarch/sub",
            "device": "testcorp,test-device",
            "profile": "testcorp_test-device",
            "version": "24.10.2",
        },
        "flash_methods": {
            "sysupgrade": {"description": "SSH sysupgrade"},
        },
        "capabilities": ["ethernet"],
    }


class _Sandbox:
    """Stage a temp dir with ``models/`` and ``schemas/`` mirroring the repo."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.models_dir = tmp_path / "models"
        self.models_dir.mkdir()
        schemas_dir = tmp_path / "schemas"
        schemas_dir.mkdir()
        self.schema_path = schemas_dir / "model.schema.json"
        self.schema_path.write_text(REAL_SCHEMA_PATH.read_text())

    def write_model(self, filename: str, data: dict) -> Path:
        path = self.models_dir / filename
        path.write_text(json.dumps(data))
        return path

    def run(self) -> tuple[int, str, str]:
        """Invoke ``validate_models.main()`` with patched constants."""
        stdout_buf, stderr_buf = io.StringIO(), io.StringIO()
        with (
            patch.object(validate_models, "MODELS_DIR", self.models_dir),
            patch.object(validate_models, "SCHEMA_PATH", self.schema_path),
            redirect_stdout(stdout_buf),
            redirect_stderr(stderr_buf),
        ):
            rc = validate_models.main()
        return rc, stdout_buf.getvalue(), stderr_buf.getvalue()


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


class ConstantsTests(TestCase):
    def test_root_is_path(self):
        self.assertIsInstance(validate_models.ROOT, Path)

    def test_root_resolves_to_repo_root(self):
        # ROOT = scripts/.. resolved
        expected = Path(validate_models.__file__).resolve().parent.parent
        self.assertEqual(validate_models.ROOT, expected)

    def test_models_dir_is_root_models(self):
        self.assertEqual(
            validate_models.MODELS_DIR, validate_models.ROOT / "models"
        )

    def test_schema_path_is_root_schemas_model_schema(self):
        self.assertEqual(
            validate_models.SCHEMA_PATH,
            validate_models.ROOT / "schemas" / "model.schema.json",
        )

    def test_real_models_dir_exists(self):
        # Sanity: the constants point at real directories
        self.assertTrue(validate_models.MODELS_DIR.is_dir())

    def test_real_schema_exists(self):
        self.assertTrue(validate_models.SCHEMA_PATH.is_file())

    def test_draft7validator_is_importable(self):
        # Ensures the try/except ImportError successfully bound the symbol
        self.assertTrue(callable(validate_models.Draft7Validator))


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


class EmptyDirTests(TestCase):
    def test_empty_models_dir_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            rc, out, err = sb.run()
            self.assertEqual(rc, 0)
            self.assertEqual(out, "")
            self.assertEqual(err, "")

    def test_non_json_files_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            (sb.models_dir / "README.md").write_text("not json")
            (sb.models_dir / "stale.txt").write_text("ignore me")
            rc, out, err = sb.run()
            self.assertEqual(rc, 0)
            self.assertEqual(out, "")


class SingleValidModelTests(TestCase):
    def test_single_valid_model_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            sb.write_model("test-device.json", _valid_model("test-device"))
            rc, out, err = sb.run()
            self.assertEqual(rc, 0)
            self.assertIn("OK: test-device.json", out)
            self.assertEqual(err, "")

    def test_ok_line_uses_filename_not_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            sb.write_model("abc-1.json", _valid_model("abc-1"))
            _, out, _ = sb.run()
            # Should contain just the basename, not the absolute path
            self.assertIn("OK: abc-1.json", out)
            self.assertNotIn(str(sb.models_dir / "abc-1.json"), out)


class MultipleValidModelsTests(TestCase):
    def test_models_are_processed_in_sorted_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            # Intentionally insert out of order
            for stem in ("zebra", "alpha", "mango", "banana"):
                sb.write_model(f"{stem}.json", _valid_model(stem))
            rc, out, err = sb.run()
            self.assertEqual(rc, 0)
            self.assertEqual(err, "")
            ok_lines = [
                line for line in out.splitlines() if line.startswith("OK: ")
            ]
            self.assertEqual(
                ok_lines,
                [
                    "OK: alpha.json",
                    "OK: banana.json",
                    "OK: mango.json",
                    "OK: zebra.json",
                ],
            )

    def test_all_valid_models_returns_zero_with_one_ok_per_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            for i in range(5):
                stem = f"dev-{i}"
                sb.write_model(f"{stem}.json", _valid_model(stem))
            rc, out, err = sb.run()
            self.assertEqual(rc, 0)
            self.assertEqual(out.count("OK: "), 5)


# ---------------------------------------------------------------------------
# id / filename-stem mismatch
# ---------------------------------------------------------------------------


class IdMismatchTests(TestCase):
    def test_id_field_differs_from_stem_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("inside-id")
            sb.write_model("outside-id.json", data)
            rc, out, err = sb.run()
            self.assertEqual(rc, 1)
            self.assertIn("FAIL: outside-id.json", err)
            self.assertIn("id 'inside-id'", err)
            self.assertIn("filename stem 'outside-id'", err)

    def test_missing_id_field_fails_with_none_in_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("noid")
            del data["id"]
            sb.write_model("noid.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            # data.get("id") returns None → message contains "id 'None'"
            self.assertIn("id 'None'", err)

    def test_id_mismatch_message_goes_to_stderr_not_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("wrong")
            sb.write_model("right.json", data)
            _, out, err = sb.run()
            self.assertIn("FAIL", err)
            self.assertNotIn("FAIL", out)


# ---------------------------------------------------------------------------
# openwrt.device WARN, openwrt.profile FAIL
# ---------------------------------------------------------------------------


class OpenwrtDeviceWarnTests(TestCase):
    def test_missing_openwrt_device_warns_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("noopdev")
            del data["openwrt"]["device"]
            sb.write_model("noopdev.json", data)
            rc, _out, err = sb.run()
            self.assertIn("WARN: noopdev.json: missing openwrt.device", err)
            # Schema still requires the field, so rc=1 from schema error,
            # but the WARN itself must be present regardless.

    def test_warn_emitted_when_device_is_empty_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("emptydev")
            data["openwrt"]["device"] = ""
            sb.write_model("emptydev.json", data)
            _, _out, err = sb.run()
            self.assertIn("WARN: emptydev.json: missing openwrt.device", err)

    def test_warn_goes_to_stderr_not_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("warnstream")
            del data["openwrt"]["device"]
            sb.write_model("warnstream.json", data)
            _, out, err = sb.run()
            self.assertIn("WARN:", err)
            self.assertNotIn("WARN:", out)


class OpenwrtProfileFailTests(TestCase):
    def test_missing_openwrt_profile_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("noprof")
            del data["openwrt"]["profile"]
            sb.write_model("noprof.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            self.assertIn("FAIL: noprof.json: missing openwrt.profile", err)
            self.assertIn("ASU ImageBuilder name", err)

    def test_empty_profile_string_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("emptyprof")
            data["openwrt"]["profile"] = ""
            sb.write_model("emptyprof.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            self.assertIn("missing openwrt.profile", err)

    def test_missing_openwrt_object_entirely_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("noopwrt")
            del data["openwrt"]
            sb.write_model("noopwrt.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            # ow = data.get("openwrt", {}) → empty dict; both device WARN and
            # profile FAIL fire, plus schema errors from required openwrt
            self.assertIn("WARN", err)
            self.assertIn("FAIL", err)


# ---------------------------------------------------------------------------
# jsonschema validation errors
# ---------------------------------------------------------------------------


class SchemaErrorTests(TestCase):
    def test_missing_required_top_level_field_reports_schema_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("novendor")
            del data["vendor"]
            sb.write_model("novendor.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            # FAIL line carries the full path (not just basename) for schema errs
            self.assertIn("FAIL:", err)
            self.assertIn("novendor.json", err)
            self.assertIn("vendor", err)

    def test_root_level_error_uses_angle_brackets_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("rootlvl")
            del data["vendor"]  # missing required field at root
            sb.write_model("rootlvl.json", data)
            _, _out, err = sb.run()
            self.assertIn("<root>:", err)

    def test_nested_error_reports_dotted_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("nested")
            # Invalid type for openwrt.target (must be string)
            data["openwrt"]["target"] = 12345
            sb.write_model("nested.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            self.assertIn("openwrt.target", err)

    def test_schema_error_returns_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("bad")
            # capabilities must be array of enum, "potato" is not allowed
            data["capabilities"] = ["potato"]
            sb.write_model("bad.json", data)
            rc, _out, _err = sb.run()
            self.assertEqual(rc, 1)

    def test_multiple_schema_errors_all_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("multi")
            del data["vendor"]
            del data["description"]
            sb.write_model("multi.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            self.assertIn("vendor", err)
            self.assertIn("description", err)

    def test_invalid_id_pattern_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("Bad_Id")  # uppercase + underscore not allowed
            sb.write_model("Bad_Id.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            self.assertIn("id", err)

    def test_flash_methods_must_have_description(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("nodesc")
            data["flash_methods"]["sysupgrade"] = {}  # missing description
            sb.write_model("nodesc.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            self.assertIn("description", err)

    def test_empty_flash_methods_object_fails_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("noflash")
            data["flash_methods"] = {}  # minProperties: 1
            sb.write_model("noflash.json", data)
            rc, _out, _err = sb.run()
            self.assertEqual(rc, 1)


# ---------------------------------------------------------------------------
# tested_hardware "note" annotation
# ---------------------------------------------------------------------------


class TestedHardwareNoteTests(TestCase):
    def test_flash_method_without_tested_entry_prints_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("untested")
            # sysupgrade exists in flash_methods but no tested_hardware
            sb.write_model("untested.json", data)
            rc, out, _err = sb.run()
            self.assertEqual(rc, 0)
            self.assertIn("note: untested.json", out)
            self.assertIn("sysupgrade", out)

    def test_all_methods_tested_no_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("alltested")
            data["tested_hardware"] = {
                "sysupgrade": {"tested": True, "date": "2026-01-01"},
            }
            sb.write_model("alltested.json", data)
            rc, out, _err = sb.run()
            self.assertEqual(rc, 0)
            self.assertNotIn("note:", out)
            self.assertIn("OK: alltested.json", out)

    def test_partially_tested_lists_only_untested(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("partial")
            data["flash_methods"]["recovery-http"] = {
                "description": "U-Boot HTTP recovery",
            }
            data["flash_methods"]["tftp"] = {"description": "TFTP boot"}
            data["tested_hardware"] = {
                "sysupgrade": {"tested": True},
            }
            sb.write_model("partial.json", data)
            rc, out, _err = sb.run()
            self.assertEqual(rc, 0)
            self.assertIn("note:", out)
            self.assertIn("recovery-http", out)
            self.assertIn("tftp", out)
            # Sysupgrade IS tested → must NOT appear in the untested list
            note_line = next(
                line for line in out.splitlines() if "note:" in line
            )
            self.assertNotIn("sysupgrade", note_line)

    def test_untested_methods_listed_alphabetically(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("sorted")
            data["flash_methods"]["zebra"] = {"description": "z"}
            data["flash_methods"]["alpha"] = {"description": "a"}
            data["flash_methods"]["mango"] = {"description": "m"}
            sb.write_model("sorted.json", data)
            _, out, _err = sb.run()
            note_line = next(
                line for line in out.splitlines() if "note:" in line
            )
            # alpha, mango, sysupgrade, zebra (alphabetical)
            self.assertLess(note_line.index("alpha"), note_line.index("mango"))
            self.assertLess(note_line.index("mango"), note_line.index("sysupgrade"))
            self.assertLess(
                note_line.index("sysupgrade"), note_line.index("zebra")
            )

    def test_note_only_appears_when_no_schema_errors(self):
        # When schema errors exist, the else branch is skipped → no "note:"
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("schemafail")
            del data["vendor"]  # forces schema error
            sb.write_model("schemafail.json", data)
            _, out, _err = sb.run()
            self.assertNotIn("note:", out)

    def test_note_message_goes_to_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("notestream")
            sb.write_model("notestream.json", data)
            _, out, err = sb.run()
            self.assertIn("note:", out)
            self.assertNotIn("note:", err)


# ---------------------------------------------------------------------------
# Mixed file scenarios (regression / interaction)
# ---------------------------------------------------------------------------


class MixedFileTests(TestCase):
    def test_one_pass_one_fail_returns_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            sb.write_model("good.json", _valid_model("good"))
            bad = _valid_model("bad")
            del bad["openwrt"]["profile"]
            sb.write_model("bad.json", bad)
            rc, out, err = sb.run()
            self.assertEqual(rc, 1)
            self.assertIn("OK: good.json", out)
            self.assertIn("FAIL: bad.json", err)

    def test_failure_in_first_file_does_not_skip_later_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            bad = _valid_model("aaa")
            del bad["openwrt"]["profile"]
            sb.write_model("aaa.json", bad)
            sb.write_model("zzz.json", _valid_model("zzz"))
            rc, out, err = sb.run()
            self.assertEqual(rc, 1)
            self.assertIn("FAIL: aaa.json", err)
            self.assertIn("OK: zzz.json", out)

    def test_id_mismatch_plus_missing_profile_both_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            data = _valid_model("inside")
            del data["openwrt"]["profile"]
            sb.write_model("outside.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            # Both FAIL lines should be present
            fails = [line for line in err.splitlines() if line.startswith("FAIL:")]
            self.assertGreaterEqual(len(fails), 2)
            self.assertTrue(any("id 'inside'" in line for line in fails))
            self.assertTrue(
                any("missing openwrt.profile" in line for line in fails)
            )

    def test_all_real_repo_models_validate(self):
        """The repo's actual models/ must validate cleanly — guards against regression."""
        stdout_buf, stderr_buf = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            rc = validate_models.main()
        self.assertEqual(
            rc,
            0,
            msg=f"Real repo models failed validation:\nSTDOUT:\n{stdout_buf.getvalue()}\nSTDERR:\n{stderr_buf.getvalue()}",
        )


# ---------------------------------------------------------------------------
# JSON sort key for error iteration
# ---------------------------------------------------------------------------


class ErrorSortingTests(TestCase):
    def test_schema_errors_sorted_by_path(self):
        """Errors are sorted by ``list(e.path)`` so output is deterministic."""
        with tempfile.TemporaryDirectory() as tmp:
            sb = _Sandbox(Path(tmp))
            # Two errors at different paths; sort order must be stable
            data = _valid_model("orderly")
            data["openwrt"]["target"] = 999  # numeric, schema wants string
            data["capabilities"] = ["definitely-not-an-enum"]
            sb.write_model("orderly.json", data)
            rc, _out, err = sb.run()
            self.assertEqual(rc, 1)
            # The capabilities error path starts ['capabilities', 0];
            # the openwrt.target path starts ['openwrt', 'target'].
            # 'capabilities' sorts before 'openwrt', so the capabilities line
            # comes first in stderr.
            cap_idx = err.find("capabilities")
            target_idx = err.find("openwrt.target")
            self.assertGreater(cap_idx, -1)
            self.assertGreater(target_idx, -1)
            self.assertLess(cap_idx, target_idx)
