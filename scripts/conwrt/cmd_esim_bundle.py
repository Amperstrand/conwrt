#!/usr/bin/env python3
"""conwrt esim-bundle — verify + side-load the eSIM toolchain onto a router (#856).

The no-internet dependency problem: a stock OpenWrt NR7101 has no lpac,
no curl-with-TLS, no GSMA CI trust anchors — and no internet to install
them (the eSIM IS the internet). The lpac-openwrt repo produces
self-contained per-arch tarballs (non-invasive bundle: everything under
/usr/lib/lpac/, private RPATH libs, augmented CA with GSMA RSP2 roots);
this driver closes the UX gap:

  1. VERIFY an artifact (sha256 + the runtime fingerprints the
     lpac-openwrt README pins: LPAC_APDU_AT_HEX, LPAC_HTTP_SSL_VERIFY,
     at_csim/http_curl drivers present, GSMA CI count in the CA bundle)
  2. GENERATE the paste-able side-load commands (scp -O + ssh tar -xzf),
     or perform the side-load itself (--push IP)
  3. STAGE the esim-http-relay script (the no-internet HTTP leg) next to
     the binary for a complete provisioning kit

Usage:
    conwrt esim-bundle --artifact lpac-25.12.6-mipsel24kc.tar.gz
    conwrt esim-bundle --artifact ... --verify-only
    conwrt esim-bundle --artifact ... --push 192.168.5.1
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: Fingerprints every r1+ lpac-openwrt artifact must carry (README §runtime).
#: NOTE: env-var option NAMES live in the DRIVER .so files, not the lpac
#: binary itself — verified against the real 25.12.6 ipq40xx artifact:
#: LPAC_APDU_AT_HEX + timerfd in driver_apdu_at_csim.so;
#: LPAC_HTTP_SSL_VERIFY + LPAC_HTTP_CURL_CAINFO in driver_http_curl.so.
REQUIRED_FINGERPRINTS = {
    "usr/lib/lpac/driver/driver_apdu_at_csim.so": [
        b"LPAC_APDU_AT_HEX",     # uppercase-hex fix (Qualcomm lowercase-CSIM class)
        b"timerfd",              # bounded at_expect deadline (the hang fix)
    ],
    "usr/lib/lpac/driver/driver_http_curl.so": [
        b"LPAC_HTTP_SSL_VERIFY",  # verify-ON default
        b"LPAC_HTTP_CURL_CAINFO", # CAINFO override
    ],
}
REQUIRED_DRIVERS = [
    "driver_apdu_at_csim.so",   # the on-router APDU path
    "driver_http_curl.so",      # the HTTPS leg
]
TRUST_STORE_PATH = "usr/lib/lpac/etc/ssl/certs/ca-certificates-gsma.crt"
#: Minimum cert count: ~120 WebPKI + 5 GSMA CI anchors. A tiny count means
#: the CA concatenation step was skipped (the TLS-verify class fails later).
MIN_CA_CERTS = 100


class BundleError(Exception):
    """Artifact verification failed — never side-load an unverified bundle."""


def _sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_artifact(path: str | Path) -> dict:
    """Verify an lpac-openwrt bundle tarball. Returns the manifest dict.

    Raises BundleError on any failure (the caller refuses to proceed —
    the AGENTS.md artifact-verification discipline: never side-load
    an unverified artifact onto a device).
    """
    path = Path(path)
    if not path.is_file():
        raise BundleError(f"artifact not found: {path}")

    # 1. sha256 sidecar (same directory, .sha256 suffix)
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if sidecar.is_file():
        want = sidecar.read_text().split()[0]
        got = _sha256(path)
        if want != got:
            raise BundleError(
                f"sha256 mismatch: expected {want[:16]}…, got {got[:16]}… — "
                "corrupted or wrong artifact; refusing to proceed")

    # 2. tarball structure + fingerprints
    with tarfile.open(path, "r:gz") as tar:
        names = tar.getnames()
        for required in ["./usr/bin/lpac"] + [
                f"./usr/lib/lpac/driver/{d}" for d in REQUIRED_DRIVERS]:
            if required not in names:
                raise BundleError(
                    f"missing {required} — not an lpac-openwrt r1+ bundle "
                    f"(found {len(names)} entries)")

        for member, fingerprints in REQUIRED_FINGERPRINTS.items():
            fp_path = f"./{member}"
            if fp_path not in names:
                raise BundleError(f"missing {member} — not a complete bundle")
            blob = tar.extractfile(fp_path).read()
            for fp in fingerprints:
                if fp not in blob:
                    raise BundleError(
                        f"fingerprint {fp.decode()} missing in {member} — "
                        "wrong artifact class (pre-r1 or foreign build)")

        ca_path = f"./{TRUST_STORE_PATH}"
        if ca_path not in names:
            raise BundleError(
                f"trust store {TRUST_STORE_PATH} missing — the GSMA CI "
                "concatenation step was skipped; TLS verify will fail")
        ca = tar.extractfile(ca_path).read()
        ca_count = ca.count(b"BEGIN CERT")
        if ca_count < MIN_CA_CERTS:
            raise BundleError(
                f"trust store has only {ca_count} certs (< {MIN_CA_CERTS}) — "
                "the WebPKI base CA was not concatenated")

    return {
        "path": str(path),
        "sha256": _sha256(path),
        "entries": len(names),
        "ca_certs": ca_count,
        "size": path.stat().st_size,
    }


def _scp_and_install(image_ip: str, artifact: str,
                     timeout: int = 120) -> tuple[int, str]:
    """scp -O the artifact and extract it on the router."""
    remote_name = os.path.basename(artifact)
    scp = subprocess.run(
        ["scp", "-O", artifact, f"root@{image_ip}:/tmp/{remote_name}"],
        capture_output=True, text=True, timeout=timeout, check=False)
    if scp.returncode != 0:
        return scp.returncode, f"scp failed: {scp.stderr.strip()[:200]}"
    install = subprocess.run(
        ["ssh", f"root@{image_ip}",
         f"tar -xzf /tmp/{remote_name} -C / && rm /tmp/{remote_name} && "
         f"lpac version && echo BUNDLE-INSTALLED"],
        capture_output=True, text=True, timeout=timeout, check=False)
    out = (install.stdout + install.stderr).strip()
    return install.returncode, out


def cmd_esim_bundle(args: argparse.Namespace) -> int:
    try:
        manifest = verify_artifact(args.artifact)
    except BundleError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1

    print(f"verified: {manifest['sha256'][:16]}… "
          f"({manifest['entries']} entries, {manifest['ca_certs']} CA certs, "
          f"{manifest['size'] // 1024} KiB)")

    if args.verify_only:
        return 0

    if args.push:
        rc, out = _scp_and_install(args.push, str(args.artifact))
        if rc != 0 or "BUNDLE-INSTALLED" not in out:
            print(f"FAIL: side-load incomplete: {out[-300:]}", file=sys.stderr)
            return 1
        print(f"installed on {args.push}: {out.splitlines()[0] if out else ''}")
        print("\nKnown-good env (next steps):")
        print(f"  export LPAC_APDU=at_csim")
        print(f"  export LPAC_APDU_AT_DEVICE=<re-detected-tty>")
        print(f"  export LPAC_APDU_AT_HEX=UPPER")
        print(f"  lpac chip info   # Gate 0: card state")
        return 0

    # Default: print the paste-able commands
    art = str(Path(args.artifact).resolve())
    print(f"\n# side-load (paste these):")
    print(f"scp -O {art} root@<router-ip>:/tmp/")
    print(f"ssh root@<router-ip> 'tar -xzf /tmp/{os.path.basename(art)} -C / "
          f"&& rm /tmp/{os.path.basename(art)} && lpac version'")
    print(f"\n# then the known-good env + Gate 0:")
    print(f"ssh root@<router-ip> 'export LPAC_APDU=at_csim "
          f"LPAC_APDU_AT_DEVICE=/dev/ttyUSB2 LPAC_APDU_AT_HEX=UPPER; "
          f"lpac chip info'")
    print(f"\n# HTTP leg (no router internet): tools/esim-http-relay/ in conwrt-bench")
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "esim-bundle",
        help="verify + side-load the eSIM toolchain onto a no-internet router (#856)")
    p.add_argument("--artifact", required=True,
                   help="path to the lpac-openwrt bundle tarball")
    p.add_argument("--verify-only", action="store_true",
                   help="verify the artifact, print the manifest, exit")
    p.add_argument("--push", default=None, metavar="IP",
                   help="side-load onto the router at IP (scp -O + tar -xzf)")
    p.set_defaults(func=cmd_esim_bundle)
