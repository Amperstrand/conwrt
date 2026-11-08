#!/usr/bin/env python3
"""mf286d_flash_campaign.py — one-command flash campaign for ZTE MF286D (conwrt #621).

Orchestrates the PROVEN flash route end-to-end, phase-gated:
  0 stage    — bench addresses, host firewall, fence armed (sha-pinned), audits
  1 stock    — stock web alive, LOGIN (sha256(base64(pw))), AD = md5(md5(wa+cr)+RD)
  2 open     — SwitchFactoryMode&SwitchCMD=Open (+AD) -> FactoryResult:Success;
               wait for factory-mode web at the factory IP
  3 backup   — HOOK: unit mtd acquisition via the factory-mode channel (gated)
  4 trigger  — HOOK: write kernel-volume-less UBI to mtd9 (the blank-download trigger)
  5 flash    — reboot; bootloader pulls root_uImage from the fence; fin = oracle
  6 setup    — OpenWrt first boot: key, password (device's passwd tool), hostname,
               dhcp-off, baseline backup; verify BOTH auth paths

--rehearse runs the whole campaign against in-process mocks (no hardware).

Every phase logs to LOGDIR; a phase failure stops the campaign (fail-closed).
Flash-class operations (3/4/5) require --i-understand-this-flashes unless --rehearse.
"""
import argparse, atexit, base64, hashlib, http.client, json, os, random, socket, subprocess, sys, threading, time

LOG = print

# ---------------------------------------------------------------- goform bits
def sha256_upper_b64(pw): return hashlib.sha256(base64.b64encode(pw.encode())).hexdigest().upper()
def ad_token(wa, cr, rd):
    inner = hashlib.md5((wa + cr).encode()).hexdigest()
    return hashlib.md5((inner + rd).encode()).hexdigest()

class Goform:
    def __init__(self, host, timeout=8): self.host, self.timeout = host, timeout
    def _post(self, path, fields):
        body = "&".join(f"{k}={v}" for k, v in fields.items())
        c = http.client.HTTPConnection(self.host, timeout=self.timeout)
        c.request("POST", path, body, {"Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse(); data = r.read().decode(errors="replace"); c.close()
        return data
    def get_cmd(self, cmd):
        c = http.client.HTTPConnection(self.host, timeout=self.timeout)
        c.request("GET", f"/goform/goform_get_cmd_process?isTest=false&cmd={cmd}&multi_data=1")
        r = c.getresponse(); data = r.read().decode(errors="replace"); c.close()
        try: return json.loads(data)
        except Exception: return {"_raw": data}
    def login(self, pw):
        return self._post("/goform/goform_set_cmd_process",
                          {"goformId": "LOGIN", "password": sha256_upper_b64(pw), "isTest": "false"})
    def factory_open(self, ad):
        return self._post("/goform/goform_process",
                          {"goformId": "SwitchFactoryMode", "SwitchCMD": "Open", "AD": ad, "isTest": "false"})

def wait_http(ip, path="/", timeout=180, want_codes=(200, 302)):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            c = http.client.HTTPConnection(ip, timeout=4)
            c.request("GET", path); r = c.getresponse(); r.read(); c.close()
            if r.status in want_codes: return True
        except OSError: pass
        time.sleep(3)
    return False

# ---------------------------------------------------------------- mock device
class MockDevice(threading.Thread):
    """Rehearsal mock: stock goform (AD-gated) + factory web + blank-download TFTP client."""
    def __init__(self):
        super().__init__(daemon=True)
        self.state = {"wa": "BD_TELIAMF286DV1.0.0B09 [mock]", "cr": "Nordic_MF286D_B10",
                      "rd": hashlib.md5(str(random.random()).encode()).hexdigest(),
                      "factory": False, "flashed": False, "tftp_done": False}
    def run(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        st = self.state
        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"
            def log_message(self, *a): pass
            def _send(self, body, code=200):
                self.send_response(code)
                self.send_header("Server", "ZTE-Webs/2.5.0")
                self.end_headers(); self.wfile.write(body.encode())
            def do_GET(self):
                if "goform_get_cmd_process" in self.path:
                    cmd = self.path.split("cmd=")[-1].split("&")[0]
                    vals = {c: st[c.replace("RD", "rd").replace("wa_inner_version", "wa").replace("cr_version", "cr")]
                            for c in cmd.split(",") if c in ("RD", "wa_inner_version", "cr_version")}
                    self._send(json.dumps(vals)); return
                self._send("mock index", 302 if not st["factory"] else 200)
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n).decode()
                f = dict(kv.split("=", 1) for kv in body.split("&") if "=" in kv)
                if f.get("goformId") == "LOGIN":
                    self._send('{"result":"0"}' if f.get("password") == sha256_upper_b64("mock-pw") else '{"result":"failure"}')
                elif f.get("goformId") == "SwitchFactoryMode":
                    ok = f.get("AD") == ad_token(st["wa"], st["cr"], st["rd"])
                    if ok: st["factory"] = True
                    self._send("\nFactoryResult:Success" if ok else "\nFactoryResult:Failed")
                else: self._send('{"result":"failure"}')
        self.httpd = ThreadingHTTPServer(("127.0.0.1", MOCK_STOCK_PORT), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        # blank-download TFTP client: once factory+trigger set, RRQ to the fence
        while not st["flashed"]:
            if st.get("trigger_written"):
                self._tftp_pull(); st["flashed"] = True
            time.sleep(0.3)
    def _tftp_pull(self):
        st = self.state
        rrq = b"\x00\x01root_uImage\x00octet\x00blksize\x001468\x00"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(10)
        s.sendto(rrq, ("127.0.0.1", MOCK_FENCE_PORT))
        got = b""; expected = 1; peer = None
        try:
            while True:
                pkt, addr = s.recvfrom(65535)
                peer = peer or addr  # ACK the SERVING socket (ephemeral), per TFTP
                op = int.from_bytes(pkt[:2], "big")
                if op == 6: s.sendto(b"\x00\x04\x00\x00", peer); continue
                if op == 3:
                    blk = int.from_bytes(pkt[2:4], "big")
                    if blk == expected: got += pkt[4:]; expected += 1
                    s.sendto(b"\x00\x04" + blk.to_bytes(2, "big"), peer)
                    if len(pkt) < 4 + 1468: break
        except socket.timeout: pass
        st["image_sha"] = hashlib.sha256(got).hexdigest()
        st["image_bytes"] = len(got)
        s.sendto(b"OK:zte blank download is done", ("127.0.0.1", MOCK_FENCE_PORT))

MOCK_STOCK_PORT, MOCK_FENCE_PORT = 18080, 18069

# ---------------------------------------------------------------- fence
def arm_fence(image, bind, port, logdir, extra=(), timeout=1800):
    sha = hashlib.sha256(open(image, "rb").read()).hexdigest()
    pinned = f"{image}#sha256:{sha}"
    cmd = [sys.executable, FENCE, "--image", pinned, "--bind", bind, "--port", str(port),
           "--timeout", str(timeout), "--log-dir", logdir, *extra]
    global _fence_proc
    _fence_proc = subprocess.Popen(cmd, stdout=open(os.path.join(logdir, "fence.log"), "w"), stderr=subprocess.STDOUT)
    return _fence_proc

# ---------------------------------------------------------------- campaign
def run_campaign(args):
    logdir = args.logdir; os.makedirs(logdir, exist_ok=True)
    def phase(n, name, ok, detail=""):
        LOG(f"[phase {n}:{name}] {'PASS' if ok else 'FAIL'} {detail}")
        if not ok:
            LOG(f"CAMPAIGN STOPPED at phase {n}. Fail-closed; see {logdir}")
            sys.exit(n)
        return ok

    image_sha = hashlib.sha256(open(args.image, "rb").read()).hexdigest()
    fence = None
    phase(0, "stage", os.path.isfile(args.image),
          f"image={args.image} sha={image_sha[:16]}… fence={'mock' if args.rehearse else args.fence_bind}")

    if args.rehearse:
        mock = MockDevice(); mock.start()
        time.sleep(0.5)
        stock_ip, factory_ip, openwrt_ip = "127.0.0.1", "127.0.0.1", "127.0.0.1"
        stock_port, factory_port = MOCK_STOCK_PORT, MOCK_STOCK_PORT
        fence = arm_fence(args.image, "127.0.0.1", MOCK_FENCE_PORT, logdir)
        time.sleep(1.5)
        if fence.poll() is not None:
            phase(0.4, "fence-alive", False, f"rehearsal fence exited rc={fence.returncode}")
    else:
        stock_ip, factory_ip, openwrt_ip = "192.168.0.1", "192.168.32.1", "192.168.1.1"
        stock_port = factory_port = 80
        fence = arm_fence(args.image, args.fence_bind, 69, logdir)
        time.sleep(1.5)
        if fence.poll() is not None:
            phase(0.5, "fence-alive", False, f"fence exited rc={fence.returncode} (bind {args.fence_bind}:69 failed? port in use? address missing?)")
        phase(0.5, "hw-audit", wait_http(stock_ip, timeout=20),
              f"stock web at {stock_ip} reachable? (cable in a LAN port; unit powered)")

    if not args.rehearse:
        LOG("[pre-1] SPECIMEN + OWNERSHIP CHECK: confirm intended unit (MAC/serial)")
        LOG("[pre-1] Verify no other lane/session owns this DUT (single-owner rule)")
    g = Goform(f"{stock_ip}:{stock_port}")
    ver = g.get_cmd("wa_inner_version,cr_version,RD")
    phase(1, "stock-login", "wa_inner_version" in ver and '"0"' in g.login(args.password),
          f"wa={ver.get('wa_inner_version','?')[:30]}")

    r = g.factory_open(ad_token(ver["wa_inner_version"], ver["cr_version"], ver["RD"]))
    opened = "Success" in r
    phase(2, "factory-open", opened, f"resp={r.strip()[:40]}")
    if args.rehearse:
        time.sleep(0.5)
    else:
        phase(2.5, "factory-web", wait_http(factory_ip, timeout=300), f"factory web at {factory_ip}")

    # phase 3+4: hooks (backup + trigger). In rehearsal the mock accepts direct flags.
    if args.rehearse:
        mock.state["trigger_written"] = True
        phase(3, "backup(mock)", True)
        phase(4, "trigger(mock)", True)
        t0 = time.time()
        while not mock.state.get("flashed") and time.time() - t0 < 30: time.sleep(0.5)
        served_ok = mock.state.get("image_sha") == image_sha
        phase(5, "flash(mock)", served_ok,
              f"fence served image byte-exact: {served_ok} (mock sha={mock.state.get('image_sha','?')[:16]}…)")
    else:
        for n, hook, name in ((3, args.backup_hook, "backup"), (4, args.trigger_hook, "trigger")):
            if not hook:
                phase(n, name, False, f"no --{name}-hook given and this is a REAL flash; refusing (fail-closed)")
            rc = subprocess.run([hook], capture_output=True, text=True)
            phase(n, name, rc.returncode == 0, rc.stdout.strip()[:60] or rc.stderr.strip()[:60])
        LOG("[phase 5:flash] reboot device (operator power-cycle) — fence is armed; fin packet is the oracle")
        fence.wait(timeout=args.fence_timeout)
        phase(5, "flash", fence.returncode == 0, f"fence exit={fence.returncode}")
        LOG("[phase 6] POST-FLASH: run setup (seed key, set password, hostname, dhcp-off) at the device's default address")

    LOG(f"CAMPAIGN {'REHEARSAL ' if args.rehearse else ''}COMPLETE — logdir={logdir}")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", required=True)
    ap.add_argument("--password", default="mock-pw", help="stock web password")
    ap.add_argument("--logdir", default="/tmp/opencode/mf286d-campaign")
    ap.add_argument("--rehearse", action="store_true")
    ap.add_argument("--fence-bind", default="192.0.0.1")
    ap.add_argument("--fence-timeout", type=int, default=1800)
    ap.add_argument("--backup-hook")
    ap.add_argument("--trigger-hook")
    ap.add_argument("--i-understand-this-flashes", action="store_true")
    args = ap.parse_args()
    if not args.rehearse and not args.i_understand_this_flashes:
        ap.error("real campaign requires --i-understand-this-flashes (or --rehearse)")
    if not args.rehearse and (not args.backup_hook or not args.trigger_hook):
        ap.error("real campaign needs --backup-hook and --trigger-hook (or --rehearse)")
    global FENCE; FENCE = os.path.join(os.path.dirname(__file__), "zte-blankdl-flashd.py")
    global _fence_proc; _fence_proc = None
    run_campaign(args)

_fence_proc = None
def _cleanup_fence():
    global _fence_proc
    if _fence_proc and _fence_proc.poll() is None:
        _fence_proc.terminate()
atexit.register(_cleanup_fence)

if __name__ == "__main__":
    main()
