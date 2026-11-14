"""VM apply-acceptance v2: FRESH overlay VM per fixture (order-effect isolation).

Each fixture: boot fresh overlay of the integration base (ephemeral port),
sh -n gate, ship via scp -O, apply, uci readbacks, kill VM. Verdicts are
independent — no shared-state contamination (v1 correction, 2026-11-14).
"""
import json
import pathlib
import socket
import subprocess
import sys
import time

REPO = pathlib.Path("/root/src/worktrees/conwrt/parity-corpus")
RENDER = pathlib.Path("/root/.cargo-target/debug/conwrt-plan-render")
FIXDIR = REPO / "tests/fixtures/parity"
KEY = REPO / "tests/integration/.vm_ssh_key"
BASE = REPO / "tests/integration/.openwrt-base.qcow2"
WORK = pathlib.Path("/tmp/apply-iso")

DEFAULTS = ["doh_default", "mwan3_default", "ssh_hardening_default",
            "vpn_ivpn_default", "tollgate_cellular_minimal", "guest_wifi_default"]


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class VM:
    def __init__(self, name: str):
        self.port = free_port()
        self.dir = WORK / name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.disk = self.dir / "v.qcow2"
        self.serial = self.dir / "serial.log"
        self.pid = self.dir / "v.pid"

    def boot(self):
        for f in (self.disk, self.serial, self.pid):
            f.unlink(missing_ok=True)
        subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                        "-b", str(BASE), str(self.disk)], check=True, capture_output=True)
        subprocess.run(["qemu-system-x86_64",
                        "-drive", f"file={self.disk},format=qcow2,if=virtio",
                        "-m", "512M",
                        "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{self.port}-:22",
                        "-device", "virtio-net-pci,netdev=net0", "-display", "none",
                        "-serial", f"file:{self.serial}", "-pidfile", str(self.pid),
                        "-daemonize", "-enable-kvm", "-cpu", "host"],
                       check=True, capture_output=True, timeout=60)
        t0 = time.time()
        while time.time() - t0 < 400:
            if self.ssh("true").returncode == 0:
                return
            time.sleep(4)
        raise RuntimeError(f"boot timeout; serial tail: "
                           f"{self.serial.read_text()[-600:] if self.serial.exists() else 'none'}")

    def ssh(self, cmd, timeout=90):
        return subprocess.run(
            ["ssh", "-F", "/dev/null", "-p", str(self.port),
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-i", str(KEY),
             "root@127.0.0.1", cmd], capture_output=True, text=True, timeout=timeout)

    def kill(self):
        if self.pid.exists():
            subprocess.run(["kill", self.pid.read_text().strip()],
                           capture_output=True)
            self.pid.unlink(missing_ok=True)


def readbacks(name, vm):
    checks = {}
    def get(k, cmd):
        checks[k] = vm.ssh(cmd, 30).stdout.strip()
    if name.startswith("mwan3"):
        get("track_ip_committed", "uci show mwan3 2>/dev/null | grep -c track_ip")
    if name.startswith("doh"):
        get("resolver_url", "uci -q get https-dns-proxy.main.resolver_url")
        get("dnsmasq_fwd", "uci -q get dhcp.@dnsmasq[0].server")
    if name.startswith("ssh_hardening"):
        get("dropbear_root_pw_login",
            "uci -q get dropbear.@dropbear[0].RootPasswordAuth")
        get("dropbear_port", "uci -q get dropbear.@dropbear[0].Port")
    return checks


def main():
    names = sys.argv[1:] or DEFAULTS
    results = {}
    for name in names:
        vm = VM(name)
        fx = FIXDIR / f"{name}.json"
        r = subprocess.run([str(RENDER), str(fx)], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            results[name] = {"render": f"FAIL {r.stderr[:160]}"}
            continue
        script = r.stdout
        syntax = subprocess.run(["sh", "-n"], input=script, capture_output=True, text=True)
        if syntax.returncode != 0:
            results[name] = {"syntax": f"FAIL {syntax.stderr[:160]}"}
            continue
        try:
            vm.boot()
            local = pathlib.Path(f"/tmp/{name}.sh"); local.write_text(script)
            subprocess.run(["scp", "-O", "-F", "/dev/null", "-P", str(vm.port),
                            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                            "-i", str(KEY), str(local), f"root@127.0.0.1:/tmp/{name}.sh"],
                           capture_output=True, timeout=60, check=True)
            a = vm.ssh(f"sh /tmp/{name}.sh; echo APPLY_RC=$?", timeout=600)
            rc = next((l for l in a.stdout.splitlines() if l.startswith("APPLY_RC=")), "APPLY_RC=?")
            # settle+retry: ssh-hardening restarts dropbear and the immediate
            # readback races it (empty uci output, found 2026-11-14)
            time.sleep(4)
            checks = readbacks(name, vm)
            for _ in range(4):
                if all(v for v in checks.values()):
                    break
                time.sleep(4)
                checks = readbacks(name, vm)
            tail = [l for l in a.stdout.splitlines() if l.strip()][-3:]
            results[name] = {"apply": rc, "checks": checks, "tail": tail}
            print(f"{name}: {rc} {checks}", flush=True)
        finally:
            vm.kill()
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
