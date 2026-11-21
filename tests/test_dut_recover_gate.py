"""#273: the recovery-upload gate accepts only the model's expected
status (+signature), never any non-000 HTTP code."""
import re
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))

SCRIPT = (Path(__file__).resolve().parent.parent / "scripts" / "dut_recover.py").read_text()


def _watcher() -> str:
    m = re.search(r'WATCHER = r"""(.*?)"""', SCRIPT, re.S)
    assert m is not None
    return m.group(1)


def test_watcher_requires_expected_status_not_any_nonzero():
    w = _watcher()
    assert 'if [ "$code" = "$EXPECT" ]' in w, "the gate must compare against the expected status"
    # the any-non-000 arm may only remain as a LOGGING elif, never the
    # accept condition: the upload must be nested inside the expect gate
    assert 'elif [ -n "$code" ] && [ "$code" != "000" ]' in w, (
        "non-matching codes are logged-and-waited, not accepted")


def test_watcher_signature_check_and_wrong_status_wait():
    w = _watcher()
    assert "grep -q \"$SIGNATURE\"" in w, "signature gate present"
    assert "not the recovery page, waiting" in w
    assert "HTTP $code != $EXPECT - not the recovery server" in w


def test_watcher_upload_only_inside_passing_gate():
    w = _watcher()
    gate = w.find('if [ "$code" = "$EXPECT" ]')
    sig = w.find("grep -q")
    upload = w.find("-F \"$FIELD=@$IMG\"")
    assert 0 < gate < sig < upload, "upload must sit inside status+signature gates"


def test_interactive_path_uses_expected_status():
    assert "live == expect" in SCRIPT, (
        "the interactive gate must compare against the model's expected status")


def test_defaults_fill_when_model_has_no_probe_config():
    assert '.replace("__EXPECT__", str(r.get("probe_expect_status", 200)))' in SCRIPT
    assert '"probe_page_signature"' in SCRIPT
