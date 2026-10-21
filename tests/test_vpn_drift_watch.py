"""vpn-drift-watch — gluetun release scan filter + escalation rules.

Fixtures are taken from REAL gluetun release bodies (verified 2026-10-14)
so the filter is calibrated against the actual format, not a guess.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

vdw = importlib.import_module("vpn-drift-watch")
escalates = vdw.escalates
provider_lines = vdw.provider_lines

# Verbatim structure from gluetun v3.41.1 (2026-02) — a provider change we
# would have wanted to know about, had it been one of ours.
REAL_BODY_PROTON = """\
## Fixes

- Healthcheck: prevent race condition making Gluetun hang completely (#3123)
- Wireguard kernelspace detection fixed in some cases
- ProtonVPN:
  - update OpenVPN settings (#3120)
  - support port 51820 for UDP OpenVPN connections
"""

# Verbatim structure from v3.40.4 — provider names appear inline too.
REAL_BODY_INLINE = """\
## Fixes

- DNS:
  - prevent restart crash if `DOT=off` and `DNS_KEEP_NAMESERVER=off`
- ExpressVPN hardcoded servers data updated (#2888)
- PureVPN OpenVPN configuration updated (from #2991)
"""


class TestProviderLines:
    def test_no_mentions_yields_nothing(self):
        assert provider_lines("Fixes\n- DNS retry logic improved") == []

    def test_named_provider_section_detected(self):
        hits = provider_lines(REAL_BODY_PROTON.replace("ProtonVPN", "NordVPN"))
        assert ("nordvpn", "- NordVPN:") in hits
        assert any(line.startswith("- update OpenVPN settings") for _p, line in hits)

    def test_pia_full_name_alias(self):
        hits = provider_lines("- Private Internet Access: update server list")
        assert hits == [("pia", "- Private Internet Access: update server list")]

    def test_inline_provider_line(self):
        hits = provider_lines(
            REAL_BODY_INLINE.replace("ExpressVPN hardcoded servers data updated",
                                     "Surfshark hardcoded servers data updated"))
        assert ("surfshark", "- Surfshark hardcoded servers data updated (#2888)") in hits

    def test_case_insensitive(self):
        hits = provider_lines("- MULLVAD: new endpoint format")
        assert hits and hits[0][0] == "mullvad"

    def test_each_line_counts_once(self):
        body = "- NordVPN and PIA both mentioned in one line"
        assert len(provider_lines(body)) == 1


class TestEscalates:
    def test_update_escalates(self):
        assert escalates("- update OpenVPN settings (#3120)") is True

    def test_removed_escalates(self):
        assert escalates("- Surfshark: removed legacy endpoint") is True

    def test_plain_mention_does_not_escalate(self):
        assert escalates("- Mullvad") is False

    def test_api_and_endpoint_words_escalate(self):
        assert escalates("- IVPN: api response shape") is True
        assert escalates("- PIA: endpoint port change") is True
