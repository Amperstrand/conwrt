"""tests/venues.py — venue resolution (PRTA transition plan §3, step S1)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from venues import Venue, venues_from_env  # noqa: E402


def _places(*names: str) -> str:
    return "\n".join(names) + "\n"


class TestEnvParsing:
    def test_default_is_qemu_session_only(self):
        assert venues_from_env(env={}, place_list=lambda: _places(),
                               protected_places=lambda: set()) == \
            [Venue("qemu-session", "qemu-session")]

    def test_explicit_list(self):
        venues = venues_from_env(
            env={"CONWRT_VENUES": "qemu-session, labgrid:ap-lan4"},
            place_list=lambda: _places("ap-lan4"),
            protected_places=lambda: set(),
        )
        assert venues == [
            Venue("qemu-session", "qemu-session"),
            Venue("labgrid:ap-lan4", "labgrid"),
        ]

    def test_direct_venue_needs_no_coordinator(self):
        venues = venues_from_env(
            env={"CONWRT_VENUES": "direct:x1860-desk"},
            place_list=lambda: _places(),
            protected_places=lambda: set(),
        )
        assert venues == [Venue("direct:x1860-desk", "direct")]

    def test_blank_tokens_ignored(self):
        venues = venues_from_env(
            env={"CONWRT_VENUES": " qemu-session , , "},
            place_list=lambda: _places(),
            protected_places=lambda: set(),
        )
        assert venues == [Venue("qemu-session", "qemu-session")]


class TestUnknownVenueSyntax:
    @pytest.mark.parametrize("bad", ["nonsense", "labgrid", ":", "vm:qemu"])
    def test_actionable_error(self, bad):
        with pytest.raises(ValueError, match="unknown venue"):
            venues_from_env(env={"CONWRT_VENUES": bad},
                            place_list=lambda: _places(),
                            protected_places=lambda: set())

    def test_unknown_kind_names_the_token(self):
        with pytest.raises(ValueError, match="unknown venue kind 'vm'"):
            venues_from_env(env={"CONWRT_VENUES": "vm:qemu"},
                            place_list=lambda: _places(),
                            protected_places=lambda: set())


class TestPlaceResolution:
    def test_unknown_place_error_mentions_registry(self):
        with pytest.raises(ValueError, match="lab_registry.py reconcile"):
            venues_from_env(env={"CONWRT_VENUES": "labgrid:ghost"},
                            place_list=lambda: _places("ap-lan2"),
                            protected_places=lambda: set())

    def test_known_place_resolves(self):
        venues = venues_from_env(
            env={"CONWRT_VENUES": "labgrid:ap-lan2"},
            place_list=lambda: _places("ap-lan2", "ap-lan3"),
            protected_places=lambda: set(),
        )
        assert venues[0].place == "ap-lan2"

    def test_place_property_none_for_qemu(self):
        venues = venues_from_env(env={}, place_list=lambda: _places(),
                                 protected_places=lambda: set())
        assert venues[0].place is None


class TestProtectedRefusal:
    def test_protected_place_refused(self):
        with pytest.raises(ValueError, match="protected"):
            venues_from_env(
                env={"CONWRT_VENUES": "labgrid:nr7101-house"},
                place_list=lambda: _places("nr7101-house"),
                protected_places=lambda: {"nr7101-house"},
            )

    def test_allow_protected_override(self):
        venues = venues_from_env(
            env={"CONWRT_VENUES": "labgrid:nr7101-house",
                 "CONWRT_VENUE_ALLOW_PROTECTED": "1"},
            place_list=lambda: _places("nr7101-house"),
            protected_places=lambda: {"nr7101-house"},
        )
        assert venues[0].place == "nr7101-house"

    def test_protection_only_queried_when_needed(self):
        calls = []

        def protected() -> set[str]:
            calls.append(1)
            return set()

        venues_from_env(env={}, place_list=lambda: _places(),
                        protected_places=protected)
        assert calls == [], "qemu-only selection must not query protection"


class TestDirectDevice:
    LAB = {"devices": {
        "x1860-desk": {"mgmt": "192.168.104.52", "ssh_port": 22,
                       "ssh_key": "~/.ssh/id_ed25519",
                       "model": "dlink-covr-x1860-a1"},
        "second-host": {"mgmt": "192.168.12.3"},
    }}

    def test_resolves_device(self):
        from venues import direct_device
        dev = direct_device("x1860-desk", lab_yaml=lambda: self.LAB)
        assert dev["host"] == "192.168.104.52"
        assert dev["port"] == 22
        assert dev["model"] == "dlink-covr-x1860-a1"

    def test_missing_registry_is_actionable(self):
        from venues import direct_device
        with pytest.raises(ValueError, match="data/lab.yaml is absent"):
            direct_device("any", lab_yaml=lambda: {})

    def test_unknown_device_names_known(self):
        from venues import direct_device
        with pytest.raises(ValueError, match=r"known: x1860-desk, second-host"):
            direct_device("ghost", lab_yaml=lambda: self.LAB)

    def test_device_without_host_refused(self):
        from venues import direct_device
        lab = {"devices": {"broken": {"state": "dark"}}}
        with pytest.raises(ValueError, match="no mgmt address"):
            direct_device("broken", lab_yaml=lambda: lab)

    def test_direct_venue_resolves_without_coordinator(self):
        # direct: needs no labgrid place list — coordinator-free resolution
        venues = venues_from_env(env={"CONWRT_VENUES": "direct:x1860-desk"},
                                 place_list=lambda: (_ for _ in ()).throw(
                                     RuntimeError("coordinator must not be queried")),
                                 protected_places=lambda: set())
        assert [v.key for v in venues] == ["direct:x1860-desk"]


class TestProtectedPlacesResolution:
    def test_missing_registry_fails_closed(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CONWRT_LAB", str(tmp_path / "no-such-checkout"))
        monkeypatch.setattr("venues.LAB_YAML", tmp_path / "no-lab.yaml")
        with pytest.raises(RuntimeError, match="no lab registry"):
            venues_from_env(
                env={"CONWRT_VENUES": "labgrid:ap-lan2"},
                place_list=lambda: "ap-lan2\n",
            )

    def test_conwrt_lab_registry_is_preferred(self, tmp_path, monkeypatch):
        import yaml as _yaml

        reg = tmp_path / "conwrt-lab"
        reg.mkdir()
        (reg / "lab.yaml").write_text(
            _yaml.safe_dump(
                {"devices": {"house-ap": {"protected": True, "labgrid_place": "ap-lan2"}}}
            )
        )
        monkeypatch.setenv("CONWRT_LAB", str(reg))
        monkeypatch.setattr("venues.LAB_YAML", tmp_path / "no-repo-copy.yaml")

        with pytest.raises(ValueError, match="protected"):
            venues_from_env(
                env={"CONWRT_VENUES": "labgrid:ap-lan2"},
                place_list=lambda: "ap-lan2\n",
            )

    def test_repo_local_registry_still_used_when_no_env(self, tmp_path, monkeypatch):
        import yaml as _yaml

        monkeypatch.delenv("CONWRT_LAB", raising=False)
        local = tmp_path / "lab.yaml"
        local.write_text(_yaml.safe_dump({"places": [{"name": "ap-lan9", "protected": True}]}))
        monkeypatch.setattr("venues.LAB_YAML", local)

        with pytest.raises(ValueError, match="protected"):
            venues_from_env(
                env={"CONWRT_VENUES": "labgrid:ap-lan9"},
                place_list=lambda: "ap-lan9\n",
            )


class TestSeparatorOnlyVenues:
    def test_separator_only_conwrt_venues_is_rejected(self):
        for raw in [",,", " , , ", ","]:
            with pytest.raises(ValueError, match="no venue"):
                venues_from_env(env={"CONWRT_VENUES": raw},
                                place_list=lambda: "",
                                protected_places=lambda: set())
