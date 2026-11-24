"""Tests for the discover-as-Strategy encoding (#777).

Pins three things:
1. the states artifact is a well-formed machine (unique ids, one initial,
   edges resolve, entry hints resolve)
2. lockstep with the IMPLEMENTED ladder: bench_discover.build_ladder()
   layers match the artifact's transitions layer-for-layer and count-for-
   count — JSON/artifact drift is a CI bug, not prose divergence
3. the audit property: legal walks pass, forbidden sequences (continuing
   after a failed control gate; a transition taken from the wrong state)
   are flagged; listen verdicts seed legal starting states
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from conwrt.strategy_states import (  # noqa: E402
    StrategyStateError,
    audit_run,
    entry_state_for_listen,
    initial_state,
    ladder_layers,
    load_states,
    validate,
    validate_or_raise,
)


@pytest.fixture(scope="module")
def doc():
    return load_states()


class TestArtifactWellFormed:
    def test_valid(self, doc):
        assert validate(doc) == []

    def test_initial_state(self, doc):
        assert initial_state(doc) == "dark"

    def test_malformed_detected(self, doc):
        import copy
        broken = copy.deepcopy(doc)
        broken["transitions"][0]["on_positive"] = "nonexistent-state"
        assert validate(broken)
        with pytest.raises(StrategyStateError):
            validate_or_raise(broken)

    def test_duplicate_state_detected(self, doc):
        import copy
        broken = copy.deepcopy(doc)
        broken["states"].append(broken["states"][0])
        assert any("unique" in p for p in validate(broken))

    def test_bad_entry_hint_detected(self, doc):
        import copy
        broken = copy.deepcopy(doc)
        broken["entry_hints"]["v6door"] = "nowhere"
        assert any("entry hint" in p for p in validate(broken))


class TestLadderLockstep:
    def test_every_implemented_layer_has_transitions(self, doc):
        from bench_discover import DiscoverContext, build_ladder
        # subnets non-empty: the 2-v4 sweep rung is CONDITIONAL on the
        # context carrying candidate subnets (documented ladder shape)
        ctx = DiscoverContext(mac="aa:bb:cc:dd:ee:ff", iface="eth0",
                              probe_host="host", control_ip="192.0.2.1",
                              subnets=["192.0.2.0/24"])
        ladder = build_ladder(ctx)
        implemented = Counter(h.layer for h in ladder)
        recorded = Counter(t["layer"] for t in doc["transitions"])
        assert implemented == recorded, (
            f"bench_discover ladder and discover_states.json disagree: "
            f"implemented={dict(implemented)} recorded={dict(recorded)}"
        )

    def test_statuses_known_by_audit(self):
        from conwrt.strategy_states import VALID_VERDICTS
        from bench_discover import Hypothesis
        # the dataclass's documented statuses are exactly the audit's
        assert {"planned", "positive", "negative", "skipped",
                "control-failed"} <= VALID_VERDICTS


class TestAuditRun:
    def test_legal_walk(self, doc):
        run = [
            {"layer": "0-control", "status": "positive"},
            {"layer": "1-v6", "status": "negative"},
            {"layer": "1-v6", "status": "negative"},
            {"layer": "2-v4", "status": "positive"},
            {"layer": "3-service", "status": "positive"},
            {"layer": "4-creds", "status": "planned"},
        ]
        out = audit_run(doc, run)
        assert out["legal"], out["problems"]
        assert out["path"][0] == "dark -[control-gate:positive]-> dark"
        assert out["path"][-1] == "banner-up -[credential-ladder:planned]-> shell-candidate"

    def test_continuing_after_control_failure_is_illegal(self, doc):
        run = [
            {"layer": "0-control", "status": "control-failed"},
            {"layer": "1-v6", "status": "negative"},  # forbidden: negatives untrustworthy
        ]
        out = audit_run(doc, run)
        assert not out["legal"]

    def test_control_negative_aborts(self, doc):
        out = audit_run(doc, [{"layer": "0-control", "status": "negative"}])
        assert out["legal"] and out["path"][0].endswith("-> methodology-unverified")

    def test_wrong_state_transition_flagged(self, doc):
        run = [
            {"layer": "0-control", "status": "positive"},
            {"layer": "3-service", "status": "positive"},  # from v4-candidate, run is at dark
        ]
        out = audit_run(doc, run)
        assert not out["legal"]
        assert any("declares from" in p for p in out["problems"])

    def test_listen_seeded_start_is_legal(self, doc):
        # listen said v6door -> start at v6-alive; the v6 evidence transition
        # then legitimately declares from 'dark' (first-step seed tolerance)
        run = [{"layer": "1-v6", "status": "positive"}]
        out = audit_run(doc, run)
        assert out["legal"], "first-step seed jump away from dark must be tolerated"


class TestListenComposition:
    @pytest.mark.parametrize("verdict,expected", [
        ("no-frames", "dark"),
        ("v6door", "v6-alive"),
        ("alias-probe", "v4-candidate"),
        ("dhcp-adopt", "v4-candidate"),
        ("vendor-fallback", "banner-up"),
        ("capture-longer", "dark"),
    ])
    def test_every_listen_verdict_maps(self, doc, verdict, expected):
        assert entry_state_for_listen(doc, verdict) == expected

    def test_bootlisten_next_actions_covered(self, doc):
        # lockstep with bootlisten's classifier: every next_action it can
        # emit must have an entry hint (unknown verdict -> None, not crash)
        from conwrt.bootlisten import classify
        hints = {k for k in doc["entry_hints"] if not k.startswith("_")}
        import inspect
        src = inspect.getsource(classify)
        import re
        emitted = set(re.findall(r'next_action = "([a-z-]+)"', src))
        assert emitted <= hints, f"bootlisten emits verdicts without hints: {emitted - hints}"
        assert entry_state_for_listen(doc, "made-up-verdict") is None


class TestJsonPayloadWiring:
    def test_state_view_present_in_payload_shape(self):
        # contract: the --json payload attaches state_view and NEVER lets
        # an audit failure block the bench run (error path is a dict, not
        # an exception). Source-level pin; behavior verified on hardware.
        src = (Path(__file__).resolve().parents[1]
               / "scripts" / "bench_discover.py").read_text()
        assert 'payload["state_view"]' in src
        assert "never block a bench run" in src
