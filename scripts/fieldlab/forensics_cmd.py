"""forensics command — pre-flash backup, TollGate detection, ecash extraction.

Run this BEFORE flashing any device that might contain data:
1. Backs up /etc as <mac>.tar.gz
2. Detects TollGate installation and version
3. Extracts CashU ecash tokens and wallet mnemonic
4. Generates a device report (model, packages, services, tollgate state)
5. Warns if sats/wallet found on device

All artifacts saved to backups/forensics/<mac>/ (gitignored).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from fieldlab.rundir import FieldLabRun

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FORENSICS_DIR = REPO_ROOT / "backups" / "forensics"

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
_PROOF_RE = re.compile(r'\{"y":"[0-9a-f]+","amount":\d+,"id":"[0-9a-f]+","secret":"[0-9a-f]+".*?\}')


def _ssh_pass(ip: str, password: str, command: str, bind: str = "",
              timeout: int = 30) -> subprocess.CompletedProcess:
    """SSH with password via sshpass."""
    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.CompletedProcess(
            args=[], returncode=127, stdout="",
            stderr="sshpass not found. Install: brew install hudochenkov/sshpass/sshpass",
        )
    cmd = [sshpass, "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10"]
    if bind:
        cmd += ["-o", f"BindAddress={bind}"]
    cmd += [f"root@{ip}", command]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _scp_pass(ip: str, password: str, remote: str, local: str, bind: str = "",
              timeout: int = 60) -> subprocess.CompletedProcess:
    """SCP download with password via sshpass."""
    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.CompletedProcess(args=[], returncode=127, stdout="", stderr="no sshpass")
    cmd = [sshpass, "-p", password, "scp", "-O", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null"]
    if bind:
        cmd += ["-o", f"BindAddress={bind}"]
    cmd += [f"root@{ip}:{remote}", local]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _extract_ecash_from_walletdb(wallet_path: Path) -> dict:
    """Extract CashU proofs and mnemonic from a BoltDB wallet.db file."""
    data = wallet_path.read_bytes()
    text = data.decode("latin-1")

    proofs = []
    for match in _PROOF_RE.finditer(text):
        try:
            proof = json.loads(match.group())
            proofs.append(proof)
        except json.JSONDecodeError:
            pass

    total_sats = sum(p.get("amount", 0) for p in proofs)

    mnemonic_match = re.search(
        r"([a-z]+(?: [a-z]+){11,23})",
        text,
    )
    mnemonic = mnemonic_match.group(1) if mnemonic_match else ""

    mint_urls = set(re.findall(r"https?://[^\s\"']+/?(?:Bitcoin)?", text))

    return {
        "proofs_found": len(proofs),
        "total_sats": total_sats,
        "mnemonic": mnemonic,
        "mints": list(mint_urls),
        "proofs": proofs,
    }


def cmd_forensics(args: argparse.Namespace, host=None) -> int:
    """Run pre-flash forensics on a device."""
    ip = args.target
    password = args.password
    bind = args.bind or ""

    if not password:
        print("[!] --password is required for forensics.", file=sys.stderr)
        return 1

    print(f"[+] Running forensics on {ip}...", file=sys.stderr)

    identity = _ssh_pass(ip, password,
        "cat /tmp/sysinfo/board_name 2>/dev/null; echo; "
        "cat /tmp/sysinfo/model 2>/dev/null; echo; "
        "cat /sys/class/net/br-lan/address 2>/dev/null || cat /sys/class/net/eth0/address 2>/dev/null; echo; "
        "cat /etc/openwrt_release 2>/dev/null | grep DISTRIB_DESCRIPTION",
        bind=bind, timeout=15)

    if identity.returncode != 0:
        print(f"[!] SSH failed: {identity.stderr.strip()}", file=sys.stderr)
        return 1

    id_parts = [p.strip() for p in identity.stdout.strip().split("\n") if p.strip()]
    board_name = id_parts[0] if len(id_parts) > 0 else "unknown"
    model = id_parts[1] if len(id_parts) > 1 else "unknown"
    mac = id_parts[2].lower().replace(":", "-") if len(id_parts) > 2 else "unknown-mac"
    release = id_parts[3] if len(id_parts) > 3 else "unknown"

    print(f"[+] Device: {model} ({board_name})", file=sys.stderr)
    print(f"[+] MAC: {mac}", file=sys.stderr)
    print(f"[+] Release: {release}", file=sys.stderr)

    device_dir = FORENSICS_DIR / mac
    device_dir.mkdir(parents=True, exist_ok=True)

    tg_check = _ssh_pass(ip, password,
        "ls /usr/bin/tollgate-wrt 2>/dev/null && echo TOLLGATE_FOUND; "
        "ls /etc/tollgate/ 2>/dev/null; "
        "cat /etc/tollgate/install.json 2>/dev/null; "
        "cat /etc/tollgate/config.json 2>/dev/null",
        bind=bind, timeout=10)

    is_tollgate = "TOLLGATE_FOUND" in tg_check.stdout
    tg_version = ""
    tg_config = {}
    ecash_data = {}

    if is_tollgate:
        print(f"[!] TOLLGATE DETECTED — this device has TollGate firmware installed!",
              file=sys.stderr)

        try:
            tg_install = json.loads(
                re.search(r'\{.*"config_version".*?\}', tg_check.stdout, re.DOTALL).group()
                if "config_version" in tg_check.stdout else "{}"
            )
            tg_version = tg_install.get("installed_version", "unknown")
        except (json.JSONDecodeError, AttributeError):
            tg_version = "unknown"

        print(f"[+] TollGate version: {tg_version}", file=sys.stderr)

        print(f"[+] Downloading TollGate wallet data...", file=sys.stderr)
        for fname in ["wallet.db", "config.json", "identities.json", "install.json"]:
            result = _scp_pass(ip, password, f"/etc/tollgate/{fname}",
                               str(device_dir / fname), bind=bind)
            if result.returncode == 0:
                print(f"    downloaded {fname}", file=sys.stderr)

        wallet_path = device_dir / "wallet.db"
        if wallet_path.exists():
            ecash_data = _extract_ecash_from_walletdb(wallet_path)
            if ecash_data["total_sats"] > 0:
                print(f"[!] WALLET CONTAINS {ecash_data['total_sats']} SATS IN ECASH!",
                      file=sys.stderr)
                print(f"    Mnemonic: {ecash_data['mnemonic']}", file=sys.stderr)
                print(f"    Mints: {', '.join(ecash_data['mints'])}", file=sys.stderr)
                print(f"    Proofs saved to {device_dir}/ecash-tokens.json",
                      file=sys.stderr)

                ecash_out = {
                    "device": model,
                    "mac": mac,
                    "extracted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "total_sats": ecash_data["total_sats"],
                    "mnemonic": ecash_data["mnemonic"],
                    "mints": ecash_data["mints"],
                    "proofs": ecash_data["proofs"],
                }
                (device_dir / "ecash-tokens.json").write_text(
                    json.dumps(ecash_out, indent=2) + "\n")
            else:
                print(f"[+] Wallet is empty (0 sats in ecash).", file=sys.stderr)
    else:
        print(f"[+] No TollGate detected.", file=sys.stderr)

    print(f"[+] Backing up /etc...", file=sys.stderr)
    etc_result = _ssh_pass(ip, password, "tar czf /tmp/etc-backup.tar.gz /etc 2>/dev/null",
                           bind=bind, timeout=30)
    if etc_result.returncode == 0:
        scp_result = _scp_pass(ip, password, "/tmp/etc-backup.tar.gz",
                               str(device_dir / f"{mac}.tar.gz"), bind=bind, timeout=60)
        if scp_result.returncode == 0:
            size = (device_dir / f"{mac}.tar.gz").stat().st_size
            print(f"    /etc backup: {size} bytes → {mac}.tar.gz", file=sys.stderr)
        _ssh_pass(ip, password, "rm /tmp/etc-backup.tar.gz 2>/dev/null", bind=bind, timeout=5)

    report = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ip": ip,
        "model": model,
        "board_name": board_name,
        "mac": mac,
        "release": release,
        "is_tollgate": is_tollgate,
        "tollgate_version": tg_version,
        "ecash_sats": ecash_data.get("total_sats", 0),
        "has_mnemonic": bool(ecash_data.get("mnemonic")),
        "warnings": [],
    }
    if is_tollgate and ecash_data.get("total_sats", 0) > 0:
        report["warnings"].append(
            f"Device has {ecash_data['total_sats']} sats in ecash — "
            "redeem before flashing! See ecash-tokens.json."
        )
    if is_tollgate:
        report["warnings"].append(
            "TollGate device — wallet.db and identities.json backed up."
        )

    (device_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    print(f"\n[+] Forensics complete. Artifacts in {device_dir}/", file=sys.stderr)
    if report["warnings"]:
        print(f"\n[!] WARNINGS:", file=sys.stderr)
        for w in report["warnings"]:
            print(f"    {w}", file=sys.stderr)

    sys.stdout.write(json.dumps(report, indent=2) + "\n")
    return 0
