"""Signet CLN client for tollgate E2E tests — clnrest (HTTPS + Rune) transport.

Python port of cashu-cf's scripts/lib/clnrest.ts pattern (the same transport
the cashu-mint-signet backend uses). Used by the host to drive REAL signet
payments in tests: pay mint invoices (NUT-04) so tests can mint ecash tokens,
and settle/observe the melt side — without any ssh/docker lightning-cli shells.

Credentials NEVER live in this repo. Resolution order:
  1. CONWRT_CLNREST_URL / CONWRT_CLNREST_RUNE env vars
  2. ~/.config/conwrt/signet-cln.json  {"url": ..., "rune": ...}

Rune hygiene (signet funds are worthless but not free to replace):
create a dedicated, restricted, rate-limited rune on the operator's node.
Alternatives inside one restriction are separate strings (OR); restrictions
are AND-ed; a bare ``rate=N`` means N calls/second::

    lightning-cli createrune null \\
        '[[ "method=xpay", "method=listpays", "method=getinfo" ], [ "rate=3" ]]'

That rune can only call xpay/listpays/getinfo, max 3 calls per second
(verified: getinfo passes, invoice returns 1502 "Not permitted", burst calls
return 1502 "too soon"). Do NOT use an unrestricted master rune for testing.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

CREDS_FILE = Path.home() / ".config" / "conwrt" / "signet-cln.json"
DEFAULT_TIMEOUT = 90


class ClnRestError(Exception):
    def __init__(self, code: Optional[int], message: str, body: str = ""):
        super().__init__(f"clnrest {code if code is not None else '?'}: {message}")
        self.code = code
        self.body = body


def load_credentials() -> tuple[str, str]:
    url = os.environ.get("CONWRT_CLNREST_URL", "")
    rune = os.environ.get("CONWRT_CLNREST_RUNE", "")
    if not url or not rune:
        if CREDS_FILE.exists():
            cfg = json.loads(CREDS_FILE.read_text())
            url = url or cfg.get("url", "")
            rune = rune or cfg.get("rune", "")
    if not url or not rune:
        raise RuntimeError(
            "signet CLN credentials not found. Set CONWRT_CLNREST_URL / "
            f"CONWRT_CLNREST_RUNE or create {CREDS_FILE} (see module docstring "
            "for the restricted-rune recipe)."
        )
    return url.rstrip("/"), rune


def credentials_available() -> bool:
    try:
        load_credentials()
        return True
    except RuntimeError:
        return False


def _rpc(method: str, params: dict[str, Any] | None = None,
         timeout: int = DEFAULT_TIMEOUT) -> Any:
    url, rune = load_credentials()
    data = json.dumps(params or {}).encode()
    req = urllib.request.Request(
        f"{url}/v1/{method}",
        data=data,
        headers={"Content-Type": "application/json", "Rune": rune},
        method="POST",
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as res:
                body = res.read().decode()
            break
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            parsed_error = _maybe_json(body)
            if "too soon" in (parsed_error or {}).get("message", "") and attempt < 2:
                time.sleep(1.0)
                continue
            raise _clnrest_error(body, e.code) from None
        except (urllib.error.URLError, OSError) as e:
            raise ClnRestError(None, f"transport error: {e}") from None
    else:  # pragma: no cover — loop always breaks or raises
        raise ClnRestError(None, "exhausted retries")
    try:
        parsed = json.loads(body)
    except ValueError:
        raise ClnRestError(None, f"non-JSON response: {body[:200]}") from None
    # clnrest error style: {"code":206,"data":null,"message":"Failed: ..."}
    if parsed.get("code") not in (None, 0) and parsed.get("data") is None \
            and parsed.get("message"):
        raise ClnRestError(parsed.get("code"), parsed["message"], body)
    return parsed.get("data", parsed)


def _maybe_json(body: str) -> dict[str, Any]:
    try:
        return json.loads(body)
    except ValueError:
        return {}


def _clnrest_error(body: str, http_code: int) -> ClnRestError:
    try:
        parsed = json.loads(body)
        return ClnRestError(parsed.get("code", http_code),
                            parsed.get("message", body[:200]), body)
    except ValueError:
        return ClnRestError(http_code, body[:200], body)


def getinfo() -> dict[str, Any]:
    return _rpc("getinfo")


def invoice(amount_sat: int, label: str, description: str = "",
            expiry_s: int = 600) -> dict[str, Any]:
    r = _rpc("invoice", {
        "amount_msat": f"{amount_sat * 1000}msat",
        "label": label,
        "description": description or label,
        "expiry": expiry_s,
    })
    return {"bolt11": r["bolt11"], "payment_hash": r["payment_hash"],
            "expires_at": r.get("expires_at")}


def xpay(bolt11: str, maxdelay: int = 1008,
         maxfee_msat: Optional[int] = None) -> dict[str, Any]:
    """xpay (v26 router); falls back to classic pay when the rune denies it
    (code 1502 = permission denied, -32601 = method not found)."""
    params: dict[str, Any] = {"invstring": bolt11, "maxdelay": maxdelay}
    if maxfee_msat is not None:
        params["maxfee"] = f"{maxfee_msat}msat"
    try:
        r = _rpc("xpay", params)
        return {**r, "ok": True}
    except ClnRestError as e:
        if e.code in (1502, -32601):
            return pay(bolt11, maxdelay=maxdelay, maxfee_msat=maxfee_msat,
                       label="xpay-fallback")
        return {"ok": False, "code": e.code, "message": str(e),
                "status": "failed"}


def pay(bolt11: str, maxdelay: int = 900, maxfee_msat: Optional[int] = None,
         label: Optional[str] = None) -> dict[str, Any]:
    params: dict[str, Any] = {"bolt11": bolt11, "maxdelay": maxdelay}
    if maxfee_msat is not None:
        params["maxfee"] = f"{maxfee_msat}msat"
    if label:
        params["label"] = label
    try:
        r = _rpc("pay", params)
        return {**r, "ok": True}
    except ClnRestError as e:
        return {"ok": False, "code": e.code, "message": str(e),
                "status": "failed"}


def listpays(payment_hash: Optional[str] = None) -> list[dict[str, Any]]:
    params = {"payment_hash": payment_hash} if payment_hash else {}
    return _rpc("listpays", params).get("pays", [])


def wait_paid(payment_hash: str, timeout_s: int = 60) -> Optional[dict[str, Any]]:
    """Poll listpays until complete/failed or timeout. Returns the final pay
    entry (status 'complete'/'failed') or None on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for p in listpays(payment_hash):
            if p.get("status") in ("complete", "failed"):
                return p
        time.sleep(2)
    return None
