"""Tests for model_loader — shared model registry reader."""
import json
import sys
import warnings
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import model_loader  # noqa: E402

SAMPLE_MODEL = {
    "id": "test-device-v1",
    "vendor": "TestCorp",
    "description": "Test device for unit tests",
    "openwrt": {
        "target": "testarch/testsub",
        "device": "testcorp,test-device-v1",
        "profile": "testcorp_test-device-v1",
        "board_name": "testcorp,test-device-v1",
        "version": "24.10.2",
    },
    "mac_oui": ["AA:BB:CC", "DD:EE:FF"],
    "flash_methods": {
        "sysupgrade": {"description": "SSH sysupgrade"},
        "recovery-http": {"description": "U-Boot HTTP recovery"},
    },
}


def _write_model(tmpdir: Path, model_id: str, data: dict) -> Path:
    """Write a model JSON file to a temp directory."""
    data = dict(data)
    data["id"] = model_id
    path = tmpdir / f"{model_id}.json"
    path.write_text(json.dumps(data))
    return path


# ---------------------------------------------------------------------------
# normalize_model_id
# ---------------------------------------------------------------------------


class TestNormalizeModelId(TestCase):
    """Tests for normalize_model_id — legacy alias mapping."""

    def test_legacy_underscore_mapped_to_hyphenated(self):
        result = model_loader.normalize_model_id("dlink_covr-x1860-a1")
        self.assertEqual(result, "dlink-covr-x1860-a1")

    def test_another_legacy_alias(self):
        result = model_loader.normalize_model_id("zyxel_nr7101")
        self.assertEqual(result, "zyxel-nr7101")

    def test_canonical_id_passes_through(self):
        result = model_loader.normalize_model_id("dlink-covr-x1860-a1")
        self.assertEqual(result, "dlink-covr-x1860-a1")

    def test_unknown_id_passes_through(self):
        result = model_loader.normalize_model_id("brand-new-device")
        self.assertEqual(result, "brand-new-device")

    def test_deprecated_id_emits_deprecation_warning(self):
        # Reset the warned set so we get a fresh warning
        model_loader._warned_aliases.discard("glinet_gl-mt3000")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = model_loader.normalize_model_id("glinet_gl-mt3000")
            self.assertEqual(result, "glinet-mt3000")
            dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            self.assertEqual(len(dep_warnings), 1)
            self.assertIn("deprecated", str(dep_warnings[0].message))
            self.assertIn("glinet_gl-mt3000", str(dep_warnings[0].message))

    def test_deprecated_id_warns_only_once(self):
        alias = "linksys_whw03"
        model_loader._warned_aliases.discard(alias)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            model_loader.normalize_model_id(alias)
            model_loader.normalize_model_id(alias)
            dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            self.assertEqual(len(dep_warnings), 1)

    def test_canonical_id_no_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            model_loader.normalize_model_id("dlink-covr-x1860-a1")
            dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            self.assertEqual(len(dep_warnings), 0)


# ---------------------------------------------------------------------------
# load_model
# ---------------------------------------------------------------------------


class TestLoadModel(TestCase):
    """Tests for load_model — loading model JSON files."""

    def test_load_by_filename_stem(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                model = model_loader.load_model("test-device-v1")
            self.assertEqual(model["id"], "test-device-v1")
            self.assertEqual(model["vendor"], "TestCorp")

    def test_load_fallback_search_by_json_id(self):
        """When filename differs from id, fallback glob finds it."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            # File is named differently from the id inside
            data = dict(SAMPLE_MODEL)
            data["id"] = "my-device"
            path = tmpdir / "renamed-file.json"
            path.write_text(json.dumps(data))
            with patch("model_loader.MODELS_DIR", tmpdir):
                model = model_loader.load_model("my-device")
            self.assertEqual(model["id"], "my-device")

    def test_file_not_found_for_nonexistent(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            with patch("model_loader.MODELS_DIR", tmpdir):
                with self.assertRaises(FileNotFoundError) as ctx:
                    model_loader.load_model("no-such-device")
                self.assertIn("no-such-device", str(ctx.exception))

    def test_value_error_when_file_id_mismatches_filename(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            # Write a file where the internal id doesn't match the filename stem
            bad_data = {"id": "wrong-id"}
            path = tmpdir / "test-device-v1.json"
            path.write_text(json.dumps(bad_data))
            with patch("model_loader.MODELS_DIR", tmpdir):
                with self.assertRaises(ValueError) as ctx:
                    model_loader.load_model("test-device-v1")
                self.assertIn("wrong-id", str(ctx.exception))
                self.assertIn("test-device-v1", str(ctx.exception))

    def test_load_normalizes_legacy_id(self):
        """load_model should normalize a legacy underscore id before loading."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "dlink-covr-x1860-a1", SAMPLE_MODEL)
            model_loader._warned_aliases.discard("dlink_covr-x1860-a1")
            with patch("model_loader.MODELS_DIR", tmpdir):
                with warnings.catch_warnings(record=True):
                    warnings.simplefilter("always")
                    model = model_loader.load_model("dlink_covr-x1860-a1")
            self.assertEqual(model["id"], "dlink-covr-x1860-a1")


# ---------------------------------------------------------------------------
# openwrt_asu_profile
# ---------------------------------------------------------------------------


class TestOpenwrtAsuProfile(TestCase):
    """Tests for openwrt_asu_profile — ASU profile extraction."""

    def test_returns_profile_from_model(self):
        profile = model_loader.openwrt_asu_profile(SAMPLE_MODEL)
        self.assertEqual(profile, "testcorp_test-device-v1")

    def test_raises_value_error_when_profile_missing(self):
        model = {"id": "no-profile-device", "openwrt": {}}
        with self.assertRaises(ValueError) as ctx:
            model_loader.openwrt_asu_profile(model)
        self.assertIn("no-profile-device", str(ctx.exception))

    def test_raises_value_error_when_openwrt_missing(self):
        model = {"id": "no-owrt"}
        with self.assertRaises(ValueError) as ctx:
            model_loader.openwrt_asu_profile(model)
        self.assertIn("no-owrt", str(ctx.exception))

    def test_raises_value_error_when_profile_empty(self):
        model = {"id": "empty-prof", "openwrt": {"profile": ""}}
        with self.assertRaises(ValueError):
            model_loader.openwrt_asu_profile(model)


# ---------------------------------------------------------------------------
# list_models
# ---------------------------------------------------------------------------


class TestListModels(TestCase):
    """Tests for list_models — loading all model definitions."""

    def test_returns_list_of_all_models(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "device-a", {"id": "device-a", "vendor": "A"})
            _write_model(tmpdir, "device-b", {"id": "device-b", "vendor": "B"})
            with patch("model_loader.MODELS_DIR", tmpdir):
                models = model_loader.list_models()
            ids = [m["id"] for m in models]
            self.assertIn("device-a", ids)
            self.assertIn("device-b", ids)
            self.assertEqual(len(models), 2)

    def test_empty_directory_returns_empty_list(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            with patch("model_loader.MODELS_DIR", tmpdir):
                models = model_loader.list_models()
            self.assertEqual(models, [])

    def test_ignores_non_json_files(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "device-a", {"id": "device-a"})
            (tmpdir / "readme.txt").write_text("not a model")
            with patch("model_loader.MODELS_DIR", tmpdir):
                models = model_loader.list_models()
            self.assertEqual(len(models), 1)

    def test_returns_sorted_order(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "zebra-z1", {"id": "zebra-z1"})
            _write_model(tmpdir, "alpha-a1", {"id": "alpha-a1"})
            with patch("model_loader.MODELS_DIR", tmpdir):
                models = model_loader.list_models()
            self.assertEqual(models[0]["id"], "alpha-a1")
            self.assertEqual(models[1]["id"], "zebra-z1")


# ---------------------------------------------------------------------------
# get_flash_method
# ---------------------------------------------------------------------------


class TestGetFlashMethod(TestCase):
    """Tests for get_flash_method — flash method lookup."""

    def test_returns_method_dict_for_valid_model_and_method(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                method = model_loader.get_flash_method("test-device-v1", "sysupgrade")
            self.assertIsNotNone(method)
            assert method is not None
            self.assertEqual(method["description"], "SSH sysupgrade")

    def test_returns_none_for_nonexistent_model(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            with patch("model_loader.MODELS_DIR", tmpdir):
                result = model_loader.get_flash_method("ghost-device", "sysupgrade")
            self.assertIsNone(result)

    def test_returns_none_for_nonexistent_method(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                result = model_loader.get_flash_method("test-device-v1", "tftp")
            self.assertIsNone(result)

    def test_returns_all_methods(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                sysupgrade = model_loader.get_flash_method("test-device-v1", "sysupgrade")
                recovery = model_loader.get_flash_method("test-device-v1", "recovery-http")
            self.assertIsNotNone(sysupgrade)
            self.assertIsNotNone(recovery)
            assert sysupgrade is not None
            assert recovery is not None
            self.assertEqual(sysupgrade["description"], "SSH sysupgrade")
            self.assertEqual(recovery["description"], "U-Boot HTTP recovery")


# ---------------------------------------------------------------------------
# find_model_by_target
# ---------------------------------------------------------------------------


class TestFindModelByTarget(TestCase):
    """Tests for find_model_by_target — OpenWrt target lookup."""

    def test_finds_model_by_target(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                model = model_loader.find_model_by_target("testarch/testsub")
            self.assertIsNotNone(model)
            assert model is not None
            self.assertEqual(model["id"], "test-device-v1")

    def test_returns_none_when_no_match(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                model = model_loader.find_model_by_target("nonexistent/target")
            self.assertIsNone(model)

    def test_empty_directory_returns_none(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            with patch("model_loader.MODELS_DIR", tmpdir):
                model = model_loader.find_model_by_target("any/target")
            self.assertIsNone(model)


# ---------------------------------------------------------------------------
# find_model_by_mac_oui
# ---------------------------------------------------------------------------


class TestFindModelByMacOui(TestCase):
    """Tests for find_model_by_mac_oui — MAC OUI prefix lookup."""

    def test_finds_model_matching_oui(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                matches = model_loader.find_model_by_mac_oui("AA:BB:CC")
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["id"], "test-device-v1")

    def test_case_insensitive_matching(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                matches = model_loader.find_model_by_mac_oui("aa:bb:cc")
            self.assertEqual(len(matches), 1)

    def test_empty_list_when_no_match(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                matches = model_loader.find_model_by_mac_oui("11:22:33")
            self.assertEqual(matches, [])

    def test_matches_on_any_of_multiple_ouis(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                matches = model_loader.find_model_by_mac_oui("DD:EE:FF")
            self.assertEqual(len(matches), 1)

    def test_empty_directory_returns_empty_list(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            with patch("model_loader.MODELS_DIR", tmpdir):
                matches = model_loader.find_model_by_mac_oui("AA:BB:CC")
            self.assertEqual(matches, [])

    def test_multiple_models_can_match(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "device-a", {
                **SAMPLE_MODEL,
                "id": "device-a",
                "mac_oui": ["AA:BB:CC"],
            })
            _write_model(tmpdir, "device-b", {
                **SAMPLE_MODEL,
                "id": "device-b",
                "mac_oui": ["AA:BB:CC", "11:22:33"],
            })
            with patch("model_loader.MODELS_DIR", tmpdir):
                matches = model_loader.find_model_by_mac_oui("AA:BB:CC")
            self.assertEqual(len(matches), 2)


# ---------------------------------------------------------------------------
# find_model_by_board_name
# ---------------------------------------------------------------------------


class TestFindModelByBoardName(TestCase):
    """Tests for find_model_by_board_name — board_name/device/id lookup."""

    def test_finds_by_openwrt_board_name(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                model = model_loader.find_model_by_board_name("testcorp,test-device-v1")
            self.assertIsNotNone(model)
            assert model is not None
            self.assertEqual(model["id"], "test-device-v1")

    def test_finds_by_openwrt_device(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                model = model_loader.find_model_by_board_name("testcorp,test-device-v1")
            self.assertIsNotNone(model)

    def test_finds_by_id_with_normalization(self):
        """board_name with underscores should match hyphenated model id."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                model = model_loader.find_model_by_board_name("test_device_v1")
            self.assertIsNotNone(model)
            assert model is not None
            self.assertEqual(model["id"], "test-device-v1")

    def test_returns_none_when_no_match(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_model(tmpdir, "test-device-v1", SAMPLE_MODEL)
            with patch("model_loader.MODELS_DIR", tmpdir):
                model = model_loader.find_model_by_board_name("nonexistent,board")
            self.assertIsNone(model)

    def test_empty_directory_returns_none(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            with patch("model_loader.MODELS_DIR", tmpdir):
                model = model_loader.find_model_by_board_name("anything")
            self.assertIsNone(model)
