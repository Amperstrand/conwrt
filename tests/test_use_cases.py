

class TestGuestWifiRadioGateOrdering:
    """#454 — the radio gate must run BEFORE the first commit: a band the
    device lacks must abort with zero partial config, and the discovery
    loop must survive set -e (missing radios fail their uci get)."""

    def test_radio_gate_precedes_first_commit(self):
        from use_cases.guest_wifi import _build_guest_wifi_ops

        rendered = "\n".join(
            getattr(op, "command", "") or getattr(op, "text", "")
            for op in _build_guest_wifi_ops({})
        )
        gate = rendered.index("no 2g radio found")
        assert rendered.index('for _r in radio0') < gate
        assert gate < rendered.index("uci set network.guest=interface"), (
            "the abort gate must fire BEFORE any network section exists"
        )
        # UciCommit ops carry config names, not commands — include them
        from profile.ops import UciCommit

        commits = [i for i, op in enumerate(_build_guest_wifi_ops({}))
                   if isinstance(op, UciCommit)]
        shell_gate = next(i for i, op in enumerate(_build_guest_wifi_ops({}))
                          if "no 2g radio found" in getattr(op, "command", ""))
        assert shell_gate < min(commits), "gate must precede every UciCommit"

    def test_discovery_loop_is_set_e_safe(self):
        from use_cases.guest_wifi import _build_guest_wifi_ops

        rendered = "\n".join(
            getattr(op, "command", "") for op in _build_guest_wifi_ops({})
        )
        assert "uci get wireless.${_r}.band 2>/dev/null || true" in rendered
        assert "exit 1" in rendered  # hard abort, not a silent skip
