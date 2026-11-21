#!/usr/bin/env python3
"""ZTE MF286D OTA CDN tool — fetch and verify signed .up packages from ZTE's DMS CDN.

URL pattern (species-level):
  https://dleu.ztems.com/zxmdmp/download.do?doWhat=getUp&filename=firmwarepackages/DE/ZTE/MF286D/<PLMN>/<FROM>-<TO>.up
The exact filename for a unit is in its cfg-param partition (DD_ObjectURI).

Usage:
  zte_cdn.py fetch <url> [outfile]     download + sha256 + inventory
  zte_cdn.py verify <dir>              verify RSA chain of an extracted package
  zte_cdn.py info <dir>                versions + structure
Chain (per update_control RE): device root (/etc/public_root.pem) + sbin pubkey ->
  package public_ver.pem (key.signature) -> root_uImage.signature / delta.signature.
"""
import hashlib, os, subprocess, sys, zipfile

def fetch(url, out):
    subprocess.run(["curl", "-sS", "-m", "600", "-o", out, url], check=True)
    h = hashlib.sha256(open(out, "rb").read()).hexdigest()
    print(f"{out}: {os.path.getsize(out)} bytes, sha256 {h}")
    if zipfile.is_zipfile(out):
        with zipfile.ZipFile(out) as z:
            for i in z.infolist():
                print(f"  {i.file_size:>10}  {i.filename}")
    else:
        print("  NOT a zip (error page?) — inspect manually")
    return h

def _dgst(pubkey, sig, target):
    return subprocess.run(["openssl", "dgst", "-sha256", "-verify", pubkey,
                           "-signature", sig, target], capture_output=True).returncode == 0

def verify(d):
    # Step 1: device-stored roots must approve the package key material.
    root = os.path.join(os.path.dirname(__file__), "trust/public_root.pem")
    if not os.path.exists(root):
        print(f"missing trust root {root} — extract from a unit dump (etc/public_root.pem)")
        return False
    ok_key = _dgst(root, os.path.join(d, "key.signature"), os.path.join(d, "public_ver.pem"))
    print(f"key.signature  vs device root : {'OK' if ok_key else 'FAIL'}")
    ok = ok_key
    for payload, sigf in (("root_uImage.mld", "root_uImage.signature"), ("delta.package", "delta.signature"), ("root_uImage", "root_uImage.signature")):
        p, s = os.path.join(d, payload), os.path.join(d, sigf)
        if os.path.exists(p) and os.path.exists(s):
            r = _dgst(os.path.join(d, "public_ver.pem"), s, p)
            print(f"{payload:16} vs package key: {'OK' if r else 'FAIL'}")
            ok = ok and r
    print("VERDICT:", "authentic per device trust chain" if ok else "NOT authentic")
    return ok

def info(d):
    for f in sorted(os.listdir(d)):
        if f.endswith(".sh") or f == "config":
            txt = open(os.path.join(d, f), errors="replace").read()
            for line in txt.splitlines()[:6]:
                print(f"{f}: {line[:120]}")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "fetch" and len(sys.argv) > 2:
        fetch(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "package.up")
    elif cmd == "verify" and len(sys.argv) > 2:
        sys.exit(0 if verify(sys.argv[2]) else 1)
    elif cmd == "info" and len(sys.argv) > 2:
        info(sys.argv[2])
    else:
        print(__doc__)
