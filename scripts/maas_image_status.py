#!/usr/bin/env python3
"""Evidence-grounded boot-image sync status for MAAS (#170).

The problem: MAAS's temporal workflow engine on resource-constrained
hosts (Pi 4B) intermittently never marks the boot-resource sync job
complete — the catalog shows resources as incomplete EVEN THOUGH the
rack controller fetched the files into image-storage. The workflow's
completion signal is a claim, not evidence.

This tool refuses to trust that claim. It cross-checks two independent
signals:

  1. the region API's boot-resources payload (declared size + the
     workflow's `complete` flag), and
  2. FILE EVIDENCE — bytes actually present in image-storage
     (a local path, or a JSON mapping produced over SSH).

Classification per resource:

  VERIFIED               file bytes >= declared size (deployable)
  VERIFIED-DESPITE-WORKFLOW   same, but the workflow still says
                         incomplete — the #170 shape: it works
  WORKFLOW-CLAIMS-COMPLETE    workflow says done, files ABSENT —
                         the dangerous lie; deploys would fail
  PARTIAL                files present but smaller than declared
  MISSING                no files, workflow not complete
  NO-EVIDENCE            no file evidence for this resource

Exit codes: 0 all VERIFIED*; 1 any not actually verified;
3 no evidence at all (no verdict without evidence — probe
positive-control rule).

Evidence sources:

  --storage-root DIR     walk DIR (run on the region host, or a
                         bind-mount of image-storage): per-resource
                         bytes = size of DIR/<name>/<arch>/ recursively
  --evidence-json FILE   {"<image-dir>": bytes, ...} — produce with:
                           ssh <pi> 'sudo python3 - <<EOF
                           import os,json,sys
                           root="/var/snap/maas/common/maas/images/boot-resources"
                           out={}
                           for n in os.listdir(root):
                               p=os.path.join(root,n)
                               if not os.path.isdir(p): continue
                               for a in os.listdir(p):
                                   q=os.path.join(p,a)
                                   if os.path.isdir(q):
                                       out[n+"/"+a]=sum(
                                           os.path.getsize(os.path.join(d,f))
                                           for d,_,fs in os.walk(q) for f in fs)
                           json.dump(out,sys.stdout)EOF'

API payload sources:

  --api URL --api-key KEY   GET /api/2.0/boot-resources/ (OAuth1)
  --api-json FILE           replay a saved payload (tests, offline)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STORAGE_ROOT_DEFAULT = "/var/snap/maas/common/maas/images/boot-resources"


@dataclass(frozen=True)
class ImageStatus:
    """One resource's classification."""

    key: str            # "<name>/<arch>"
    declared_size: int  # bytes per the API (0 = unknown)
    file_bytes: int     # bytes of file evidence (0 = none seen)
    complete: bool      # the workflow's claim
    status: str         # classification string

    @property
    def verified(self) -> bool:
        return self.status in ("VERIFIED", "VERIFIED-DESPITE-WORKFLOW")


def parse_api_payload(payload: Any) -> list[dict[str, Any]]:
    """Normalize a boot-resources API payload to flat resource dicts.

    Defensive on purpose: MAAS nests resources under `sets` with
    release-dependent shapes, and this tool must not crash on a shape
    it has not seen — it must degrade to reporting what it found.
    """
    if isinstance(payload, dict) and "resources" in payload:
        payload = payload["resources"]
    if not isinstance(payload, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        arch = entry.get("arch")
        if not name or not arch:
            continue
        size = entry.get("size", 0)
        try:
            size = int(size or 0)
        except (TypeError, ValueError):
            size = 0
        out.append(
            {
                "key": f"{name}/{arch}",
                "name": name,
                "declared_size": size,
                "complete": bool(entry.get("complete", False)),
            }
        )
    return out


def evidence_for(resource: dict[str, Any], evidence: dict[str, int]) -> int | None:
    """File bytes for one resource, or None when absent/ambiguous.

    MAAS resource names carry the series ("ubuntu/noble") and arch
    strings carry the HWE channel ("amd64/ga-24.04"), so full keys
    ("ubuntu/noble/amd64/ga-24.04") almost never match evidence keyed
    at the image level ("ubuntu/noble"). Matching rule, strictest
    first: exact full key; exact name; a single name-prefixed key.
    Anything ambiguous is not evidence.
    """
    if resource["key"] in evidence:
        return evidence[resource["key"]]
    if resource["name"] in evidence:
        return evidence[resource["name"]]
    prefix = resource["name"] + "/"
    matches = [k for k in evidence if k.startswith(prefix)]
    if len(matches) == 1:
        return evidence[matches[0]]
    return None


def evidence_from_storage_root(root: Path) -> dict[str, int]:
    """Bytes per `<name>/<arch>` directory under a storage root."""
    out: dict[str, int] = {}
    if not root.is_dir():
        return out
    for name_dir in root.iterdir():
        if not name_dir.is_dir():
            continue
        for arch_dir in name_dir.iterdir():
            if not arch_dir.is_dir():
                continue
            out[f"{name_dir.name}/{arch_dir.name}"] = sum(
                f.stat().st_size for f in arch_dir.rglob("*") if f.is_file()
            )
    return out


def classify(
    resources: list[dict[str, Any]],
    evidence: dict[str, int],
    evidence_covers_all: bool = False,
) -> list[ImageStatus]:
    """The #170 rule set: files are truth; the workflow flag is a hint.

    `evidence_covers_all` marks evidence from a complete walk of the
    storage root: a resource absent from it has ZERO bytes (the
    dangerous WORKFLOW-CLAIMS-COMPLETE case). A partial mapping (SSH
    probe of selected dirs) leaves absent resources at NO-EVIDENCE —
    unmeasured is not zero.
    """
    out: list[ImageStatus] = []
    for r in resources:
        declared = r["declared_size"]
        complete = r["complete"]
        file_bytes = evidence_for(r, evidence)
        if file_bytes is None and evidence_covers_all:
            file_bytes = 0
        if file_bytes is None:
            status = "NO-EVIDENCE"
            file_bytes = 0
        elif declared == 0:
            status = "UNKNOWN-DECLARED-SIZE"
        elif file_bytes >= declared:
            status = "VERIFIED" if complete else "VERIFIED-DESPITE-WORKFLOW"
        elif file_bytes > 0:
            status = "PARTIAL"
        else:
            status = "WORKFLOW-CLAIMS-COMPLETE" if complete else "MISSING"
        out.append(
            ImageStatus(
                key=r["key"],
                declared_size=declared,
                file_bytes=file_bytes,
                complete=complete,
                status=status,
            )
        )
    return out


def fetch_api_payload(url: str, api_key: str) -> Any:
    """GET the boot-resources list over the region API (OAuth1 PLAINTEXT)."""
    ck, token, secret = (api_key.split(":") + ["", ""])[:3]
    auth = (
        f'OAuth oauth_version="1.0", oauth_signature_method="PLAINTEXT", '
        f'oauth_consumer_key="{ck}", oauth_token="{token}", '
        f'oauth_signature="{secret}&"'
    )
    endpoint = url.rstrip("/") + "/api/2.0/boot-resources/"
    result = subprocess.run(
        ["curl", "-sS", "-f", "-H", f"Authorization: {auth}", endpoint],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"boot-resources query failed: {result.stderr.strip()[-200:]}"
        )
    return json.loads(result.stdout)


def report(statuses: list[ImageStatus], as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                [s.__dict__ for s in statuses],
                indent=2,
                sort_keys=True,
            )
        )
        return
    if not statuses:
        print("no resources parsed from the API payload")
        return
    width = max(len(s.key) for s in statuses)
    for s in statuses:
        flag = "workflow:complete" if s.complete else "workflow:incomplete"
        print(
            f"{s.key:<{width}}  {s.status:<28} "
            f"{s.file_bytes:>12,} / {s.declared_size:>12,} B  [{flag}]"
        )


def main() -> int:
    return main_with_argv(None)


def main_with_argv(argv: list[str] | None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--api", metavar="URL", help="region base URL")
    src.add_argument("--api-json", metavar="FILE", help="saved payload")
    covered = False
    ev = parser.add_mutually_exclusive_group()
    ev.add_argument("--storage-root", type=Path, help="local image-storage dir")
    ev.add_argument("--evidence-json", metavar="FILE", help="bytes-per-key JSON")
    parser.add_argument("--api-key", help="MAAS api key (with --api)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args(argv)

    if args.api and not args.api_key:
        parser.error("--api requires --api-key (or replay with --api-json)")

    if args.api:
        try:
            payload = fetch_api_payload(args.api, args.api_key)
        except (RuntimeError, json.JSONDecodeError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    else:
        payload = json.loads(Path(args.api_json).read_text())

    if args.storage_root is not None:
        evidence = evidence_from_storage_root(args.storage_root)
        covered = bool(evidence) or args.storage_root.is_dir()
    elif args.evidence_json:
        evidence = {
            k: int(v) for k, v in json.loads(Path(args.evidence_json).read_text()).items()
        }
    else:
        evidence = {}

    statuses = classify(parse_api_payload(payload), evidence, covered)
    report(statuses, args.json)

    if not evidence:
        print(
            "\nno file evidence given — refusing to verdict "
            "(pass --storage-root or --evidence-json)",
            file=sys.stderr,
        )
        return 3
    if all(s.verified for s in statuses):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
