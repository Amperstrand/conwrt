"""Tests for scripts/maas_image_status.py (#170).

The temporal workflow's `complete` flag is a claim; file bytes are
evidence. These tests pin every classification, both lie directions,
and the no-verdict-without-evidence exit rule.
"""

import json

import pytest

import maas_image_status as mis  # scripts/ is on pytest's pythonpath


def payload(*resources: dict) -> list[dict]:
    return list(resources)


def resource(key: str, size: int, complete: bool) -> dict:
    name, _, arch = key.partition("/")
    return {"name": name, "arch": arch, "size": size, "complete": complete}


def parsed(key: str, size: int, complete: bool) -> dict:
    return mis.parse_api_payload(payload(resource(key, size, complete)))[0]


class TestParse:
    def test_flat_list_normalizes(self):
        p = payload(resource("ubuntu/noble", 600_000_000, False))
        parsed = mis.parse_api_payload(p)
        assert parsed == [
            {
                "key": "ubuntu/noble",
                "name": "ubuntu",
                "declared_size": 600_000_000,
                "complete": False,
            }
        ]

    def test_wrapped_resources_key_unwraps(self):
        p = {"resources": [resource("ubuntu/noble", 1, True)]}
        assert mis.parse_api_payload(p)[0]["key"] == "ubuntu/noble"

    def test_missing_size_degrades_to_zero(self):
        p = [{"name": "ubuntu/noble", "arch": "amd64/ga-24.04"}]
        assert mis.parse_api_payload(p)[0]["declared_size"] == 0

    def test_nameless_entries_skipped(self):
        assert mis.parse_api_payload([{"arch": "amd64"}, "junk", 7]) == []


class TestClassify:
    def test_the_170_shape_files_match_workflow_incomplete(self):
        """The bug: sync shows incomplete despite working."""
        statuses = mis.classify(
            [parsed("ubuntu/noble", 100, False)],
            {"ubuntu/noble": 100},
        )
        assert statuses[0].status == "VERIFIED-DESPITE-WORKFLOW"
        assert statuses[0].verified

    def test_ordinary_verified_when_both_agree(self):
        statuses = mis.classify(
            [parsed("ubuntu/noble", 100, True)],
            {"ubuntu/noble": 150},
        )
        assert statuses[0].status == "VERIFIED"

    def test_workflow_claims_complete_without_files(self):
        """The dangerous opposite lie: deploys would fail."""
        statuses = mis.classify(
            [parsed("ubuntu/noble", 100, True)],
            {"ubuntu/noble": 0},
        )
        assert statuses[0].status == "WORKFLOW-CLAIMS-COMPLETE"
        assert not statuses[0].verified

    def test_partial_download(self):
        statuses = mis.classify(
            [parsed("ubuntu/noble", 100, False)],
            {"ubuntu/noble": 40},
        )
        assert statuses[0].status == "PARTIAL"

    def test_missing_entirely(self):
        statuses = mis.classify(
            [parsed("ubuntu/noble", 100, False)],
            {"ubuntu/noble": 0},
        )
        assert statuses[0].status == "MISSING"

    def test_slash_arch_matches_name_level_evidence(self):
        """Arch strings contain slashes; evidence is per image dir."""
        r = mis.parse_api_payload(
            payload(resource("ubuntu/amd64/ga-24.04", 100, False))
        )[0]
        statuses = mis.classify([r], {"ubuntu/noble": 100})
        assert statuses[0].status == "VERIFIED-DESPITE-WORKFLOW"

    def test_storage_coverage_treats_absent_as_zero(self):
        """A full walk knows: absent dir = 0 bytes = the dangerous lie."""
        r = mis.parse_api_payload(
            payload(resource("ubuntu/jammy/amd64", 100, True))
        )[0]
        statuses = mis.classify([r], {"ubuntu/jammy": 0}, True)
        assert statuses[0].status == "WORKFLOW-CLAIMS-COMPLETE"

    def test_partial_evidence_treats_absent_as_unmeasured(self):
        r = mis.parse_api_payload(
            payload(resource("ubuntu/jammy/amd64", 100, True))
        )[0]
        statuses = mis.classify([r], {"other": 5}, False)
        assert statuses[0].status == "NO-EVIDENCE"

    def test_ambiguous_name_level_evidence_is_not_evidence(self):
        r = mis.parse_api_payload(
            payload(resource("ubuntu/amd64/ga-24.04", 100, False))
        )[0]
        evidence = {"ubuntu/noble": 100, "ubuntu/jammy": 100}
        statuses = mis.classify([r], evidence)
        assert statuses[0].status == "NO-EVIDENCE"

    def test_no_evidence_for_key(self):
        statuses = mis.classify(
            [parsed("ubuntu/noble", 100, True)],
            {},
        )
        assert statuses[0].status == "NO-EVIDENCE"
        assert not statuses[0].verified

    def test_unknown_declared_size_is_not_verified(self):
        statuses = mis.classify(
            [parsed("ubuntu/noble", 0, False)],
            {"ubuntu/noble": 500},
        )
        assert statuses[0].status == "UNKNOWN-DECLARED-SIZE"


class TestStorageRootEvidence:
    def test_bytes_summed_per_name_arch(self, tmp_path):
        noble = tmp_path / "ubuntu" / "noble"
        noble.mkdir(parents=True)
        (noble / "boot.img").write_bytes(b"x" * 100)
        sub = noble / "sub"
        sub.mkdir()
        (sub / "extra").write_bytes(b"y" * 50)
        (tmp_path / "ubuntu" / "README").write_text("not a dir level we map")

        evidence = mis.evidence_from_storage_root(tmp_path)
        assert evidence["ubuntu/noble"] == 150
        assert "ubuntu/README" not in evidence

    def test_absent_root_gives_empty_evidence(self, tmp_path):
        assert mis.evidence_from_storage_root(tmp_path / "nope") == {}


class TestMainExitCodes:
    def make_files(self, tmp_path, payload_obj, evidence_obj):
        api = tmp_path / "api.json"
        api.write_text(json.dumps(payload_obj))
        ev = tmp_path / "ev.json"
        ev.write_text(json.dumps(evidence_obj))
        return ["--api-json", str(api), "--evidence-json", str(ev)]

    def test_all_verified_exits_zero(self, tmp_path, capsys):
        argv = self.make_files(
            tmp_path,
            [resource("ubuntu/noble", 100, False)],
            {"ubuntu/noble": 100},
        )
        rc = mis.main_with_argv(argv)
        assert rc == 0
        assert "VERIFIED-DESPITE-WORKFLOW" in capsys.readouterr().out

    def test_workflow_lie_exits_one(self, tmp_path):
        argv = self.make_files(
            tmp_path,
            [resource("ubuntu/noble", 100, True)],
            {"ubuntu/noble": 0},
        )
        assert mis.main_with_argv(argv) == 1

    def test_no_evidence_refuses_verdict_exit_three(self, tmp_path, capsys):
        argv = self.make_files(tmp_path, [resource("ubuntu/noble", 100, False)], {})
        rc = mis.main_with_argv(argv)
        assert rc == 3
        assert "refusing to verdict" in capsys.readouterr().err

    def test_api_without_key_is_a_usage_error(self, tmp_path):
        with pytest.raises(SystemExit) as e:
            mis.main_with_argv(["--api", "http://maas:5240/MAAS"])
        assert e.value.code == 2
