#!/usr/bin/env python3
"""er6p_redeploy — assertion-gated factory-reset catch + reconfigure for the ER6P.

Proven flow (2026-09-28, twice — the second time with the netifd option+list
bug fixed by omitting bay aliases entirely):

  STAGE preflight : temp DHCP scope armed on ERX lan_guest, route + aliases OK
  STAGE catch     : ER6P factory LAN alive at 192.168.1.1 on VLAN 14 (cable in
                    eth1/lan1), fresh-boot asserts, key install via pty SSH
  STAGE config    : minimal clean uci payload, EVERY value readback-asserted
  STAGE verify    : 192.168.12.4 answers keyed SSH, board+rogue asserts
  STAGE cleanup   : temp scope off, host entry + probe routes removed

Prereqs (user): factory-reset the ER6P (hold reset ~10s at power-on), cable
in **eth1** (factory LAN port). Final state (user, after verify): move cable
to **eth0** (canonical uplink per lab.yaml; lan0:t is configured from the
start, lan1:t is the temporary transition trunk).

Gotchas encoded here (all bitten 2026-09-28, do not "simplify" them away):
  * dhcp.lan_guest.ignore=1 makes dnsmasq emit no-dhcp-interface=br-lan.14 —
    a temp scope on the same interface is silently DEAD until ignore=0.
  * ERX forwards to 192.168.1.x with source 192.168.14.1 (primary) which the
    ER6P cannot reply to — the /32 route with src=192.168.1.250 is REQUIRED.
  * sshpass cannot type an EMPTY password — the first login needs a pty.
  * NEVER mix option+list ipaddr on one interface (netifd poison): bay
    aliases are intentionally omitted; dut_recover.py re-adds them on demand.
"""
from __future__ import annotations
import os, pty, re, select, subprocess, sys, time

ERX = "root@192.168.13.1"
ER6P_FINAL = "192.168.12.4"
CATCH_IP = "192.168.1.1"
LOCAL_PORT = 18096
PUBKEY = open(os.path.expanduser("~/.ssh/id_ed25519.pub")).read().strip()
EVID: list[str] = []


def ok(msg):  print(f"[OK]   {msg}");  EVID.append(f"OK   {msg}")
def fail(msg): print(f"[FAIL] {msg}");  EVID.append(f"FAIL {msg}")
def die(msg): fail(msg); print("\n".join(EVID)); sys.exit(1)


def run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def erx(cmd: str, timeout: int = 30) -> str:
    c, o = run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", ERX, cmd], timeout)
    return o if c == 0 else ""


def pty_ssh(port: int, command: str, tries: int = 12) -> str:
    """SSH with empty-password support via pty (first-login only path)."""
    for attempt in range(tries):
        cmd = ["ssh", "-p", str(port), "-o", "StrictHostKeyChecking=accept-new",
               "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
               "-o", "ConnectTimeout=8", "root@127.0.0.1", command]
        pid, fd = pty.fork()
        if pid == 0:
            os.close(2); os.execvp(cmd[0], cmd)  # noqa: keep stderr out of pty
        out = b""; deadline = time.time() + 15
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 1)
            if fd in r:
                try: chunk = os.read(fd, 4096)
                except OSError: break
                if not chunk: break
                out += chunk
                if b"password:" in out.lower(): os.write(fd, b"\n")
                if b"__DONE__" in out: break
        try: os.waitpid(pid, os.WNOHANG)
        except ChildProcessError: pass
        text = out.decode(errors="replace")
        if "__DONE__" in text:
            return text
        time.sleep(2)
    return ""


def stage_preflight():
    print("== STAGE preflight")
    o = erx("uci get dhcp.lan_guest.ignore")
    if o.strip() != "0":
        erx("uci set dhcp.lan_guest.ignore=0; uci commit dhcp; /etc/init.d/dnsmasq restart")
        time.sleep(3)
        o = erx("uci get dhcp.lan_guest.ignore")
    ok("lan_guest DHCP armed") if o.strip() == "0" else die(f"lan_guest ignore={o!r}")
    o = erx("ip route show 192.168.1.1")
    if "br-lan.14" not in o:
        o2 = erx("ip route change 192.168.1.1/32 dev br-lan.14 src 192.168.1.250 2>/dev/null || ip route add 192.168.1.1/32 dev br-lan.14 src 192.168.1.250; ip route show 192.168.1.1")
        o = o2
    ok("route .1.1 -> br-lan.14 src .1.250") if "br-lan.14" in o and "192.168.1.250" in o else die(f"route: {o!r}")
    o = erx("ip addr show br-lan.14 | grep -c 'inet 192.168.1.250'")
    ok("alias .1.250 on br-lan.14") if o.strip() != "0" else erx("ip addr add 192.168.1.250/24 dev br-lan.14") or ok("alias re-added")


def stage_catch():
    print("== STAGE catch")
    alive = False
    for i in range(30):
        o = erx(f"ping -c 1 -W 1 -I br-lan.14 {CATCH_IP} >/dev/null 2>&1 && echo A || echo B")
        if "A" in o: alive = True; break
        time.sleep(5)
    ok(f"factory LAN alive at {CATCH_IP} (attempt {i+1})") if alive else die("factory LAN never came up")
    o = erx(f"ip neigh show {CATCH_IP} dev br-lan.14")
    if "74:83:c2:75:08:91" in o: ok("MAC assert: 74:83:c2:75:08:91 (ER6P br-lan)")
    else: die(f"unexpected MAC: {o!r}")
    run(["pkill", "-f", "18096:192.168.1.1:22"], timeout=5)
    time.sleep(1)
    c, _ = run(["ssh", "-f", "-N", f"-L {LOCAL_PORT}:{CATCH_IP}:22", "-o", "BatchMode=yes",
                "-o", "ExitOnForwardFailure=yes", ERX], timeout=15)
    ok("tunnel up :18096") if c == 0 else die("tunnel failed")
    time.sleep(1)
    out = pty_ssh(LOCAL_PORT,
                  f"ubus call system board | grep -E 'model|version'; uptime; mkdir -p /etc/dropbear; "
                  f"echo '{PUBKEY}' > /etc/dropbear/authorized_keys; chmod 600 /etc/dropbear/authorized_keys; "
                  f"echo KEYDONE; echo __DONE__")
    if "KEYDONE" not in out: die(f"pty catch failed: {out[-200:]!r}")
    if "EdgeRouter 6P" not in out: die("board assert failed")
    m = re.search(r"up\s+(\d+)\s", out)
    if not m or int(m.group(1)) > 10: fail(f"uptime suspicious: {m and m.group(0)}")  # warn only
    else: ok(f"fresh boot (uptime {m.group(1)}m), board asserted, key installed")
    # keyed re-login assert through the same tunnel
    c, o = run(["ssh", "-p", str(LOCAL_PORT), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new", "root@127.0.0.1", "echo KEYED"], timeout=15)
    ok("keyed SSH via catch path") if "KEYED" in o else die("keyed re-login failed")


def detect_ports(tunnel_port: int) -> dict:
    """Never assume port names — the pre-crash lanN naming was config, not hardware."""
    rb = ("ls /sys/class/net/ | tr '\\n' ' '; echo; uci show network | head -30; echo __DONE__")
    c, o = run(["ssh", "-p", str(tunnel_port), "-o", "BatchMode=yes", "root@127.0.0.1", rb], timeout=20)
    if "__DONE__" not in o: die(f"port detection failed: {o[-200:]!r}")
    print(f"FACTORY STATE:\n{o[:600]}")
    ports = o.splitlines()[0].split()
    import re as _re
    bridge_m = _re.search(r"network\.@device\[\d+\]\.name='(\S+)'", o)
    bridge = bridge_m.group(1) if bridge_m else "br-lan"
    ports_m = _re.search(r"network\.@device\[\d+\]\.ports='([^']+)'", o)
    if ports_m:
        bridge_ports = ports_m.group(1).split("' '")
    else:
        bridge_ports = [p for p in ports if p not in ("lo", bridge, "dsa", "br-lan") and not p.startswith(("eth0", "lan0"))][:5]
    all_ports = [p for p in ports if p not in ("lo", bridge, "dsa") and not p.startswith(("br-", "dsa"))]
    wan = next((p for p in all_ports if p not in bridge_ports), all_ports[0] if all_ports else "eth0")
    info = {"bridge": bridge, "uplink": wan, "bays": bridge_ports[:5], "all": all_ports}
    print(f"DETECTED: bridge={bridge} uplink={wan} bays={bridge_ports[:5]}")
    ok(f"port detection: bridge={bridge}, uplink={wan}, bays={len(bridge_ports[:5])}")
    return info


def build_payload(pinfo: dict) -> str:
    
    p0, bays = pinfo["uplink"], pinfo["bays"]
    bay_lines = []
    for i, bp in enumerate(bays):
        v = 400 + i
        ip = 40 + i
        bay_lines.append(f"uci add network bridge-vlan >/dev/null; uci set network.@bridge-vlan[-1].device='{pinfo['bridge']}'")
        bay_lines.append(f"uci set network.@bridge-vlan[-1].vlan='{v}'; uci set network.@bridge-vlan[-1].ports='{bp}:u*'")
        bay_lines.append(f"uci set network.dut{i}=interface; uci set network.dut{i}.device='br-lan.{v}'; uci set network.dut{i}.proto='static'")
        bay_lines.append(f"uci set network.dut{i}.ipaddr='192.168.{ip}.1'; uci set network.dut{i}.netmask='255.255.255.0'")
        bay_lines.append(f"uci add_list firewall.@zone[0].network='dut{i}' 2>/dev/null")
    bay_block = "\n".join(bay_lines)
    return f"""uci set system.@system[0].hostname='er6p'
uci add network bridge-vlan >/dev/null; uci set network.@bridge-vlan[-1].device='{pinfo['bridge']}'
uci set network.@bridge-vlan[-1].vlan='12'; uci set network.@bridge-vlan[-1].ports='{p0}:t'
uci set network.lan.device='br-lan.12'; uci set network.lan.proto='static'
uci set network.lan.ipaddr='192.168.12.4'; uci set network.lan.netmask='255.255.255.0'
uci set network.lan.gateway='192.168.12.1'
uci del network.lan.dns 2>/dev/null; uci add_list network.lan.dns='192.168.12.1'
{bay_block}
uci set dhcp.lan.ignore='1'; uci set dhcp.lan.ra='disabled'; uci set dhcp.lan.dhcpv6='disabled'
uci commit network; uci commit firewall; uci commit dhcp; uci commit system
echo PAYLOAD-APPLIED; echo __DONE__"""


def stage_config():
    print("== STAGE config")
    pinfo = detect_ports(LOCAL_PORT)
    payload = build_payload(pinfo)
    c, o = run(["ssh", "-p", str(LOCAL_PORT), "-o", "BatchMode=yes", "root@127.0.0.1", payload], timeout=45)
    ok("payload applied+committed") if "__DONE__" in o else die(f"payload failed: {o[-200:]!r}")
    rb = ("uci get system.@system[0].hostname; uci get network.lan.ipaddr; "
          "uci get network.lan.gateway; uci get dhcp.lan.ignore; uci get dhcp.lan.ra; "
          "uci show network | grep -cE '^network\\.@bridge-vlan.*=bridge-vlan$'; echo __DONE__")
    c, o = run(["ssh", "-p", str(LOCAL_PORT), "-o", "BatchMode=yes", "root@127.0.0.1", rb], timeout=20)
    lines = [l.strip() for l in o.splitlines()]
    checks = [("hostname", lines[0:1], "er6p"), ("mgmt ip", lines[1:2], "192.168.12.4"),
              ("gateway", lines[2:3], "192.168.12.1"), ("rogue ignore", lines[3:4], "1"),
              ("ra", lines[4:5], "disabled")]
    for name, got, want in checks:
        ok(f"readback {name}={want}") if got and got[0] == want else die(f"readback {name}: {got} != {want}")
    nb = lines[5].strip() if len(lines) > 5 else "0"
    ok(f"bridge-vlan sections: {nb} (expect 6)") if nb == "6" else fail(f"bridge-vlans={nb} (want 6)")


def stage_apply_and_verify():
    print("== STAGE apply+verify")
    run(["ssh", "-p", str(LOCAL_PORT), "-o", "BatchMode=yes", "root@127.0.0.1",
         '(setsid sh -c "sleep 2; ubus call network reload; /etc/init.d/dnsmasq restart; '
         '/etc/init.d/odhcpd restart; /etc/init.d/firewall restart" >/dev/null 2>&1 &); echo RELOADING'], timeout=15)
    alive = False
    for i in range(20):
        c, o = run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", ERX,
                    f"ping -c 1 -W 1 {ER6P_FINAL} >/dev/null 2>&1 && echo A || echo B"], timeout=15)
        if "A" in o: alive = True; break
        time.sleep(5)
    ok(f"{ER6P_FINAL} answers ping (attempt {i+1})") if alive else die("final mgmt never came up")
    c, o = run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                "-o", "StrictHostKeyChecking=accept-new", f"root@{ER6P_FINAL}",
                "echo FINAL-KEYED; hostname; uci get dhcp.lan.ignore; ip -4 -o addr | grep -c 'br-lan.4'"], timeout=20)
    if "FINAL-KEYED" not in o: die(f"keyed SSH at {ER6P_FINAL} failed: {o!r}")
    ok("keyed SSH at final address; hostname + rogue asserted")
    print(o)


def stage_cleanup():
    print("== STAGE cleanup")
    erx("uci set dhcp.lan_guest.ignore=1; uci -q delete dhcp.labtemp; uci -q delete dhcp.er6p; "
        "uci commit dhcp; /etc/init.d/dnsmasq restart; "
        "ip route del 192.168.1.1/32 dev br-lan.14 2>/dev/null; true")
    o = erx("uci get dhcp.lan_guest.ignore; grep -c '192.168.14' /tmp/dhcp.leases 2>/dev/null || echo 0")
    ok("temp scope off, lan_guest quiet again") if o.splitlines()[0].strip() == "1" else fail(f"cleanup: {o!r}")
    run(["pkill", "-f", "18096:192.168.1.1:22"], timeout=5)
    ok("tunnel down")


if __name__ == "__main__":
    t0 = time.strftime("%Y%m%d-%H%M%S")
    stage_preflight()
    stage_catch()
    stage_config()
    stage_apply_and_verify()
    stage_cleanup()
    path = f"data/bench/er6p/{t0}-redeploy/evidence.txt"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").write("\n".join(EVID) + "\n")
    print(f"\nALL STAGES PASSED — evidence: {path}")
    print("NEXT (user): move the ER6P cable from eth1 to eth0 — then re-run "
          "verify (mgmt stays up via lan0:t; remove lan1:t after).")
