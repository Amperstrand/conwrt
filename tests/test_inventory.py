"""Tests for scripts/inventory.py — append-only JSONL inventory system."""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from inventory import append_to_inventory, find_device, read_inventory


class TestInventory(TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._inv_path = os.path.join(self._tmpdir, "test_inventory.jsonl")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)


# ── append_to_inventory ──────────────────────────────────────────────

class TestAppendToInventory(TestInventory):

    def test_creates_file_if_not_exists(self):
        assert not os.path.exists(self._inv_path)
        append_to_inventory({"device_serial": "SN001"}, self._inv_path)
        assert os.path.isfile(self._inv_path)

    def test_appends_single_entry(self):
        entry = {"device_serial": "SN001", "model": "MT3000"}
        append_to_inventory(entry, self._inv_path)
        entries = read_inventory(self._inv_path)
        assert len(entries) == 1
        assert entries[0] == entry

    def test_appends_multiple_entries_file_grows(self):
        for i in range(3):
            append_to_inventory({"device_serial": f"SN{i:03d}"}, self._inv_path)
        entries = read_inventory(self._inv_path)
        assert len(entries) == 3
        assert entries[0]["device_serial"] == "SN000"
        assert entries[2]["device_serial"] == "SN002"

    def test_creates_parent_directory(self):
        nested = os.path.join(self._tmpdir, "a", "b", "c", "inv.jsonl")
        append_to_inventory({"device_serial": "SN001"}, nested)
        assert os.path.isfile(nested)
        assert read_inventory(nested) == [{"device_serial": "SN001"}]

    def test_entry_is_valid_json_per_line(self):
        append_to_inventory({"device_serial": "SN001", "model": "MT3000"}, self._inv_path)
        with open(self._inv_path) as f:
            line = f.readline().strip()
        parsed = json.loads(line)
        assert parsed == {"device_serial": "SN001", "model": "MT3000"}

    def test_entry_keys_sorted(self):
        entry = {"z_key": 1, "a_key": 2, "m_key": 3}
        append_to_inventory(entry, self._inv_path)
        with open(self._inv_path) as f:
            line = f.readline().strip()
        keys = list(json.loads(line).keys())
        assert keys == sorted(keys)


# ── read_inventory ───────────────────────────────────────────────────

class TestReadInventory(TestInventory):

    def test_returns_empty_list_when_file_not_exists(self):
        assert read_inventory(self._inv_path) == []

    def test_returns_empty_list_for_empty_file(self):
        Path(self._inv_path).touch()
        assert read_inventory(self._inv_path) == []

    def test_returns_list_of_dicts_for_valid_jsonl(self):
        with open(self._inv_path, "w") as f:
            f.write(json.dumps({"a": 1}) + "\n")
            f.write(json.dumps({"b": 2}) + "\n")
        entries = read_inventory(self._inv_path)
        assert entries == [{"a": 1}, {"b": 2}]

    def test_skips_blank_lines(self):
        with open(self._inv_path, "w") as f:
            f.write(json.dumps({"a": 1}) + "\n")
            f.write("\n")
            f.write("   \n")
            f.write(json.dumps({"b": 2}) + "\n")
        entries = read_inventory(self._inv_path)
        assert len(entries) == 2

    def test_skips_malformed_json(self):
        with open(self._inv_path, "w") as f:
            f.write(json.dumps({"good": True}) + "\n")
            f.write("{bad json\n")
            f.write("not json at all\n")
            f.write(json.dumps({"also_good": True}) + "\n")
        entries = read_inventory(self._inv_path)
        assert len(entries) == 2
        assert entries[0] == {"good": True}
        assert entries[1] == {"also_good": True}

    def test_preserves_entry_order(self):
        for i in range(5):
            append_to_inventory({"idx": i}, self._inv_path)
        entries = read_inventory(self._inv_path)
        idxs = [e["idx"] for e in entries]
        assert idxs == [0, 1, 2, 3, 4]

    def test_file_with_only_blank_lines_returns_empty(self):
        with open(self._inv_path, "w") as f:
            f.write("\n\n   \n\n")
        assert read_inventory(self._inv_path) == []


# ── find_device ──────────────────────────────────────────────────────

class TestFindDevice(TestInventory):

    def test_finds_device_by_exact_serial(self):
        append_to_inventory({"device_serial": "SN001", "model": "MT3000"}, self._inv_path)
        result = find_device("SN001", self._inv_path)
        assert result is not None
        assert result["device_serial"] == "SN001"
        assert result["model"] == "MT3000"

    def test_returns_none_when_no_match(self):
        append_to_inventory({"device_serial": "SN001"}, self._inv_path)
        assert find_device("SN999", self._inv_path) is None

    def test_returns_first_match_when_multiple_entries(self):
        append_to_inventory({"device_serial": "SN001", "note": "first"}, self._inv_path)
        append_to_inventory({"device_serial": "SN001", "note": "second"}, self._inv_path)
        result = find_device("SN001", self._inv_path)
        assert result is not None
        assert result["note"] == "first"

    def test_works_with_empty_inventory(self):
        assert find_device("SN001", self._inv_path) is None

    def test_no_cross_match(self):
        append_to_inventory({"device_serial": "SN001"}, self._inv_path)
        append_to_inventory({"device_serial": "SN002"}, self._inv_path)
        result = find_device("SN002", self._inv_path)
        assert result is not None
        assert result["device_serial"] == "SN002"


# ── Roundtrip ────────────────────────────────────────────────────────

class TestRoundtrip(TestInventory):

    def test_append_read_roundtrip(self):
        entry = {"device_serial": "SN001", "model": "MT3000", "vendor": "GL.iNet"}
        append_to_inventory(entry, self._inv_path)
        entries = read_inventory(self._inv_path)
        assert entries == [entry]

    def test_append_multiple_read_roundtrip(self):
        entries = [{"device_serial": f"SN{i:03d}", "model": f"M{i}"} for i in range(5)]
        for e in entries:
            append_to_inventory(e, self._inv_path)
        assert read_inventory(self._inv_path) == entries

    def test_append_find_roundtrip(self):
        append_to_inventory({"device_serial": "SN001", "model": "MT3000"}, self._inv_path)
        append_to_inventory({"device_serial": "SN002", "model": "AR150"}, self._inv_path)
        found = find_device("SN002", self._inv_path)
        assert found == {"device_serial": "SN002", "model": "AR150"}


# ── Edge cases ───────────────────────────────────────────────────────

class TestEdgeCases(TestInventory):

    def test_unicode_values(self):
        entry = {"device_serial": "SN001", "notes": "テスト — ﬁrmwäre ©"}
        append_to_inventory(entry, self._inv_path)
        assert read_inventory(self._inv_path)[0] == entry

    def test_nested_data(self):
        entry = {
            "device_serial": "SN001",
            "mac_addresses": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
            "metadata": {"nested": {"deep": True}},
        }
        append_to_inventory(entry, self._inv_path)
        assert read_inventory(self._inv_path)[0] == entry

    def test_large_number_of_entries(self):
        for i in range(150):
            append_to_inventory({"device_serial": f"SN{i:04d}"}, self._inv_path)
        entries = read_inventory(self._inv_path)
        assert len(entries) == 150
        assert entries[0]["device_serial"] == "SN0000"
        assert entries[149]["device_serial"] == "SN0149"

    def test_serial_with_special_characters(self):
        serial = "SN/001:RX-2024#v2"
        append_to_inventory({"device_serial": serial}, self._inv_path)
        found = find_device(serial, self._inv_path)
        assert found is not None
        assert found["device_serial"] == serial

    def test_entry_with_boolean_and_none_values(self):
        entry = {"device_serial": "SN001", "password_set": False, "notes": None}
        append_to_inventory(entry, self._inv_path)
        result = read_inventory(self._inv_path)[0]
        assert result["password_set"] is False
        assert result["notes"] is None

    def test_entry_with_empty_string_values(self):
        entry = {"device_serial": "SN001", "model": "", "vendor": ""}
        append_to_inventory(entry, self._inv_path)
        assert read_inventory(self._inv_path)[0] == entry

    def test_find_device_with_empty_string_serial(self):
        append_to_inventory({"device_serial": "", "model": "unknown"}, self._inv_path)
        result = find_device("", self._inv_path)
        assert result is not None
        assert result["model"] == "unknown"
