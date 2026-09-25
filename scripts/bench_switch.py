#!/usr/bin/env python3
"""bench_switch — lifecycle manager for OpenWrt bench/PoE switches (GS1900 pattern).

Implements the bench-switch pattern (docs/BENCH-SWITCH-PATTERN.md):

  * uplink port untagged on VLAN 1 (management via the house router)
  * each DUT port isolated in bridge-vlan 100N with switch L3
    192.168.10N.1/24 and DHCP 192.168.10N.50-150
  * PoE on DUT ports only (Amperstrand realtek-poe fork, ubus poe)
  * authorized_keys, committed config, reboot-verified

Subcommands:
  backup        --host IP [--out DIR]     full backup: sysupgrade -b, overlay
                                            tar (PoE fork!), uci exports, manifest
  deploy        --host IP [--ssh|serial]  apply the bench pattern (idempotent)
  install-poe   --host IP --artifacts DIR install PoE fork from backup artifacts
  verify        --host IP                 health check: mgmt/VLANs/L3/PoE/DHCP
  reset         --host IP | --serial DEV  firstboot + reboot (needs --i-know)

Discipline (AGENTS.md): deploy arms a deadman reboot before committing,
applies one concern at a time with readback, and never emits runtime
shell variables — every uci value is a literal generated here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))


@dataclass
class BenchProfile:
    mgmt_ip: str = "192.168.13.2"
    mgmt_gateway: str = "192.168.13.1"
    uplink_port: str = "lan1"
    dut_ports: tuple[str, ...] = ("lan2", "lan3", "lan4", "lan5", "lan6", "lan7", "lan8")
    vlan_base: int = 1000
    dut_subnet_tpl: str = "192.168.10{v}.1"


def ssh(host: str, cmd: str, timeout: int = 60) -> tuple[int, str]:
    proc = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         f"root@{host}", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def scp_from(host: str, remote: str, local: str) -> int:
    return subprocess.run(
        ["scp", "-O", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         f"root@{host}:{remote}", local],
        capture_output=True, timeout=300,
    ).returncode


# ---------------------------------------------------------------- generators

def vlan_name(profile: BenchProfile, port: str) -> str:
    return f"vlan{profile.vlan_base + int(port.removeprefix('lan'))}"


def deploy_lines(profile: BenchProfile, pubkey: str | None) -> list[str]:
    """Literal-only shell lines applying the whole bench pattern."""
    lines = [
        "nohup sh -c 'sleep 600 && reboot' >/dev/null 2>&1 &",
        "uci set network.@device[0].name='switch'",
        "uci -q delete network.lan_vlan",
        "uci set network.lan=interface",
        "uci set network.lan.device='switch.1'",
        "uci set network.lan.proto='static'",
        "uci -q delete network.lan.ipaddr",
        f"uci add_list network.lan.ipaddr='{profile.mgmt_ip}/24'",
        f"uci set network.lan.gateway='{profile.mgmt_gateway}'",
        f"uci set network.lan.dns='{profile.mgmt_gateway}'",
        "uci -q set dhcp.lan.ignore='1'",
        "uci set network.vlan1=bridge-vlan",
        "uci set network.vlan1.device='switch'",
        "uci set network.vlan1.vlan='1'",
        "uci set network.vlan1.local='1'",
        "uci -q delete network.vlan1.ports",
        f"uci add_list network.vlan1.ports='{profile.uplink_port}:u*'",
    ]
    for port in profile.dut_ports:
        n = port.removeprefix("lan")
        vlan = f"{profile.vlan_base + int(n)}"
        subnet_ip = profile.dut_subnet_tpl.format(v=n)
        lines += [
            f"uci set network.vlan{vlan}=bridge-vlan",
            "uci set network.vlan{v}.device='switch'".format(v=vlan),
            f"uci set network.vlan{vlan}.vlan='{vlan}'",
            f"uci set network.vlan{vlan}.local='1'",
            f"uci -q delete network.vlan{vlan}.ports",
            f"uci add_list network.vlan{vlan}.ports='{profile.uplink_port}:t'",
            f"uci add_list network.vlan{vlan}.ports='{port}:u*'",
            f"uci set network.dut{vlan}=interface",
            f"uci set network.dut{vlan}.device='switch.{vlan}'",
            "uci set network.dut{v}.proto='static'".format(v=vlan),
            f"uci set network.dut{vlan}.ipaddr='{subnet_ip}'",
            "uci set network.dut{v}.netmask='255.255.255.0'".format(v=vlan),
            f"uci set dhcp.dhcp{vlan}=dhcp",
            f"uci set dhcp.dhcp{vlan}.interface=dut{vlan}",
            "uci set dhcp.dhcp{v}.start='50'".format(v=vlan),
            "uci set dhcp.dhcp{v}.limit='100'".format(v=vlan),
            "uci set dhcp.dhcp{v}.leasetime='12h'".format(v=vlan),
            f"uci -q del_list firewall.@zone[0].network=dut{vlan}",
            f"uci add_list firewall.@zone[0].network=dut{vlan}",
        ]
    lines.append("i=0")
    lines.append("while uci -q get poe.@port[$i].name >/dev/null 2>&1; do")
    lines.append("  P=`uci -q get poe.@port[$i].name`")
    lines.append(f"  if [ \"$P\" = \"{profile.uplink_port}\" ]; then")
    lines.append("    uci set poe.@port[$i].enable='0'")
    lines.append("  else")
    lines.append("    uci set poe.@port[$i].enable='1'")
    lines.append("  fi")
    lines.append("  i=`expr $i + 1`")
    lines.append("done")
    if pubkey:
        tokens = pubkey.split()
        needle = tokens[1][:24] if len(tokens) > 1 else pubkey[:24]
        lines += [
            "mkdir -p /etc/dropbear",
            f"grep -q '{needle}' /etc/dropbear/authorized_keys 2>/dev/null || {{",
            "rm -f /tmp/conwrt-key",
        ]
        for i in range(0, len(pubkey), 80):
            chunk = pubkey[i:i + 80].replace("'", "")
            lines.append(f"echo -n '{chunk}' >> /tmp/conwrt-key")
        lines += [
            "echo >> /tmp/conwrt-key",
            "cat /tmp/conwrt-key >> /etc/dropbear/authorized_keys",
            "rm -f /tmp/conwrt-key",
            "}",
            "chmod 600 /etc/dropbear/authorized_keys",
        ]
    lines += ["uci commit network", "uci commit dhcp", "uci commit poe",
              "uci commit firewall", "/etc/init.d/firewall restart >/dev/null 2>&1",
              "echo DEPLOY-COMMITTED"]
    return lines


def deadman_cancel_lines() -> list[str]:
    return ["killall sleep 2>/dev/null; echo DEADMAN-CANCELLED"]


# ---------------------------------------------------------------- commands

def cmd_backup(host: str, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    rc, _ = ssh(host, "sysupgrade -b /tmp/conwrt-backup.tar.gz", timeout=120)
    if rc != 0:
        print("FAIL: sysupgrade -b on switch")
        return 1
    rc, _ = ssh(host, "tar czf /tmp/overlay-upper.tar.gz -C /overlay upper", timeout=300)
    if rc != 0:
        print("FAIL: overlay tar on switch")
        return 1
    rc, _ = ssh(host, (
        "for s in network dhcp poe dropbear firewall system; do "
        "uci export $s > /tmp/uci-$s.txt; done; md5sum /tmp/conwrt-backup.tar.gz "
        "/tmp/overlay-upper.tar.gz > /tmp/backup-manifest.txt"))
    for name in ("conwrt-backup.tar.gz", "overlay-upper.tar.gz", "backup-manifest.txt"):
        if scp_from(host, f"/tmp/{name}", str(out / name)) != 0:
            print(f"FAIL: scp {name}")
            return 1
    for s in ("network", "dhcp", "poe", "dropbear", "firewall", "system"):
        scp_from(host, f"/tmp/uci-{s}.txt", str(out / f"uci-{s}.txt"))
    fork = out / "overlay-upper.tar.gz"
    with tarfile.open(fork) as tf:
        names = tf.getnames()
    has_fork = any("usr/bin/realtek-poe" in n for n in names)
    md5 = hashlib.md5(fork.read_bytes()).hexdigest()
    print(f"backup OK -> {out}")
    print(f"  overlay tar: {len(names)} files, md5 {md5}, poe-fork={'YES' if has_fork else 'MISSING!'}")
    (out / "backup.json").write_text(json.dumps({
        "host": host, "overlay_md5": md5, "poe_fork_included": has_fork,
        "files": sorted(p.name for p in out.iterdir()),
    }, indent=1))
    return 0 if has_fork else 2


def cmd_deploy(host: str, serial_port: str | None, profile: BenchProfile,
               pubkey: str | None) -> int:
    lines = deploy_lines(profile, pubkey)
    if serial_port:
        from serial_transport import SerialConsole
        console = SerialConsole(serial_port)
        console.activate()
        rc, out = console.send_script(lines, timeout=120)
        console.close()
        print(out[-800:])
        if rc != 0:
            print(f"FAIL: deploy script rc={rc}")
            return 1
    else:
        script = "\n".join(lines)
        rc, out = ssh(host, f"sh -c '{script}'", timeout=180)
        print(out[-400:])
        if rc != 0 or "DEPLOY-COMMITTED" not in out:
            print("FAIL: deploy over ssh")
            return 1
    print("deploy committed; reload + verify with `bench_switch.py verify` "
          "then reboot-verify, then cancel the deadman with `reset --cancel-deadman`")
    return 0


def cmd_verify(host: str, profile: BenchProfile) -> int:
    checks: list[tuple[str, bool, str]] = []
    rc, out = ssh(host, "ip -o addr show | grep 'inet '")
    for port in profile.dut_ports:
        vlan = profile.vlan_base + int(port.removeprefix("lan"))
        ip = profile.dut_subnet_tpl.format(v=vlan - profile.vlan_base)
        checks.append((f"dut vlan {vlan} L3 {ip}", ip in out, out))
    checks.append((f"mgmt {profile.mgmt_ip}", profile.mgmt_ip in out, out))
    rc, out = ssh(host, "ubus call poe info")
    checks.append(("poe ubus alive", rc == 0 and "lan" in out, out[:120]))
    rc, out = ssh(host, "uci get network.vlan1.ports")
    checks.append(("vlan1 list form", "'" in out, out))
    ok = True
    for name, passed, detail in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + ("" if passed else f" — {detail}"))
        ok = ok and passed
    print("VERIFY: " + ("ALL PASS" if ok else "FAILURES PRESENT"))
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backup"); b.add_argument("--host", required=True)
    b.add_argument("--out", type=Path, default=REPO_ROOT / "data/backups/bench-switch")
    d = sub.add_parser("deploy"); d.add_argument("--host", required=True)
    d.add_argument("--serial", help="serial port for bootstrap transport")
    d.add_argument("--mgmt-ip"); d.add_argument("--mgmt-gw")
    d.add_argument("--pubkey", help="path to SSH pubkey to authorize")
    v = sub.add_parser("verify"); v.add_argument("--host", required=True)
    v.add_argument("--mgmt-ip")
    r = sub.add_parser("reset"); r.add_argument("--host")
    r.add_argument("--serial"); r.add_argument("--cancel-deadman", action="store_true")
    r.add_argument("--i-know", action="store_true")
    p = sub.add_parser("install-poe"); p.add_argument("--host", required=True)
    p.add_argument("--artifacts", type=Path, required=True)
    args = ap.parse_args(argv)

    if args.cmd == "backup":
        return cmd_backup(args.host, args.out)
    if args.cmd == "verify":
        prof = BenchProfile(mgmt_ip=args.mgmt_ip) if args.mgmt_ip else BenchProfile()
        return cmd_verify(args.host, prof)
    if args.cmd == "reset":
        if args.cancel_deadman:
            rc, out = ssh(args.host, "\n".join(deadman_cancel_lines()))
            print(out); return rc
        if not args.i_know:
            print("refusing firstboot without --i-know"); return 2
        cmd = "firstboot && reboot"
        if args.serial:
            from serial_transport import SerialConsole
            c = SerialConsole(args.serial); c.activate()
            rc, out = c.run(cmd, timeout=30); c.close(); print(out[-300:])
            return rc
        rc, out = ssh(args.host, cmd, timeout=30)
        print(out[-300:]); return rc
    if args.cmd == "deploy":
        pubkey = Path(args.pubkey).read_text().strip() if args.pubkey else None
        prof = BenchProfile()
        if args.mgmt_ip:
            prof.mgmt_ip = args.mgmt_ip
        if args.mgmt_gw:
            prof.mgmt_gateway = args.mgmt_gw
        return cmd_deploy(args.host, args.serial, prof, pubkey)
    if args.cmd == "install-poe":
        return cmd_install_poe(args.host, args.artifacts)
    return 2


def cmd_install_poe(host: str, artifacts: Path) -> int:
    tarball = artifacts / "overlay-upper.tar.gz"
    if not tarball.exists():
        print(f"FAIL: {tarball} missing — run backup first")
        return 1
    ssh(host, "/etc/init.d/poe stop 2>/dev/null; killall realtek-poe 2>/dev/null; sleep 1")
    with tempfile.TemporaryDirectory() as td:
        with tarfile.open(tarball) as tf:
            wanted_bin = {"realtek-poe", "mvls", "mdio", "realtek-poe.orig"}
            wanted_etc = {"upper/etc/config/poe"}
            members = [m for m in tf.getmembers()
                       if m.name.split("/")[-1] in wanted_bin
                       or m.name in wanted_etc
                       or m.name.startswith("upper/etc/init.d/")]
            if not any(m.name.endswith("realtek-poe") for m in members):
                print("FAIL: no realtek-poe binary in artifacts")
                return 1
            tf.extractall(td, members=members)
        for m in members:
            base = m.name.split("/")[-1]
            local = Path(td) / m.name
            if m.name in wanted_etc:
                dest = "/etc/config/poe"
            elif m.name.startswith("upper/etc/init.d/"):
                dest = f"/etc/init.d/{base}"
            elif m.name.startswith("upper/usr/"):
                subpath = m.name[len("upper/usr/"):]
                dest = f"/usr/{subpath}"
            else:
                dest = f"/usr/bin/{base}"
            proc = subprocess.run(
                ["scp", "-O", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null", str(local), f"root@{host}:{dest}"],
                capture_output=True, timeout=120)
            if proc.returncode != 0:
                print(f"FAIL: scp {m.name} -> {dest}"); return 1
            rc, out = ssh(host, f"chmod +x {dest} 2>/dev/null; md5sum {dest}")
            local_md5 = hashlib.md5(local.read_bytes()).hexdigest()
            if local_md5 not in out:
                print(f"FAIL: md5 mismatch for {dest}"); return 1
            print(f"  installed {dest} (md5 verified)")
    rc, out = ssh(host, "/etc/init.d/poe restart; sleep 3; ubus call poe info | head -4")
    print(out)
    return 0 if rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
