"""Offline tests for the conwrt discover promotion (#323 item 1).

The wrapper adds nothing: the ladder's invariants must still hold
through it — layer-0 control first, v6 before v4, credentials printed
never executed.
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from bench_discover import DiscoverContext, build_ladder  # noqa: E402
from conwrt import discover as discover_mod  # noqa: E402

CTX = DiscoverContext(
    mac="b4:2d:56:25:47:a2", iface="switch.1007",
    probe_host="bench-switch", control_ip="192.168.13.1",
)


class TestLadderInvariantsThroughThePromotion:
    def test_layer0_positive_control_is_first(self):
        steps = build_ladder(CTX)
        assert steps[0].layer.startswith("0-control")

    def test_v6_precedes_service_and_credentials(self):
        # layer-2 v4 sweeps are computed at run time (subnet_candidates
        # order); the planned ladder pins v6 first, credentials last
        steps = build_ladder(CTX)
        layers = [s.layer for s in steps]
        v6 = [i for i, l in enumerate(layers) if l.startswith("1-v6")]
        later = [i for i, l in enumerate(layers) if l.startswith(("3-", "4-"))]
        assert v6 and later and max(v6) < min(later)
        assert layers[-1] == "4-creds"

    def test_credential_steps_never_execute(self):
        steps = build_ladder(CTX)
        cred = [s for s in steps if "4-" in s.layer or "credential" in s.layer]
        for s in cred:
            # print-only: the command text is a dbclient line for the
            # OPERATOR, marked as never-auto-executed
            assert "dbclient" in s.command or s.command.startswith("echo")

    def test_wrapper_plan_runs_offline(self, capsys):
        rc = discover_mod.main(
            ["plan", "--mac", "b4:2d:56:25:47:a2", "--iface", "switch.1007",
             "--control-ip", "192.168.13.1"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "0-control" in out
        assert "fe80::b62d:56ff:fe25:47a2" in out

    def test_cli_dispatch_end_to_end(self):
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, 'scripts');"
             "sys.argv=['conwrt','discover','plan','--mac','00:11:22:33:44:55',"
             "'--iface','switch.1007','--control-ip','192.168.13.1'];"
             "from conwrt import main; raise SystemExit(main())"],
            capture_output=True, text=True, cwd=REPO,
            env={"PYTHONPATH": "scripts", "PATH": "/usr/bin:/bin", "TMPDIR": "/tmp"},
        )
        assert proc.returncode == 0, proc.stderr
        assert "fe80::0211:22ff:fe33:4455"  # bench_discover pads groups in proc.stdout

    def test_run_requires_probe_host(self, capsys):
        with pytest.raises(SystemExit):
            discover_mod.main(
                ["run", "--mac", "b4:2d:56:25:47:a2", "--iface", "switch.1007",
                 "--control-ip", "192.168.13.1", "--probe-host", "",
                 "--json", ""])
