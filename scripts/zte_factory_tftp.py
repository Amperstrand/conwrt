#!/usr/bin/env python3
"""
factory_tftp.py — ZTE MF286D factory-download TFTP server + Sahara/UDP watcher.
Binds UDP/69 (default) on the single interface facing the device (192.168.32.2),
serves ANY requested filename from --root (armprg.bin, *.fbf.gz, etc.),
answers RFC2348/2349 options (blksize/timeout/tsize), and hex-logs every packet.
Non-TFTP UDP on the same port (e.g. Sahara HELLO) is logged with a marker.

Usage:
  sudo python3 factory_tftp.py --bind 192.168.32.2 --port 69 --root UPDATE/
Selftest:
  python3 factory_tftp.py --selftest
"""
import argparse, os, socket, struct, sys, time, threading, secrets

log_lock = threading.Lock()
LOGF = None
def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    with log_lock:
        print(line)
        if LOGF: LOGF.write(line + '\n'); LOGF.flush()

class Transfer:
    def __init__(self, path, blksize, sock, peer, timeout):
        self.data = open(path, 'rb').read()
        self.blksize = blksize
        self.sock, self.peer, self.timeout = sock, peer, timeout
        self.block = 0
        self.offset = -self.blksize
        self.retries = 0
        self.start = time.time()

    def next_block(self):
        self.block = 1 if self.block == 65535 else self.block + 1   # RFC2348 rollover
        self.offset += self.blksize
        off = self.offset
        chunk = self.data[off:off + self.blksize]
        return struct.pack('!HH', 3, self.block) + chunk

    def run(self):
        log(f"[TFTP] serving {len(self.data)} bytes, blksize={self.blksize} to {self.peer}")
        last = self.next_block()
        try:
            while True:
                self.sock.sendto(last, self.peer)
                try:
                    self.sock.settimeout(self.timeout)
                    pkt, _ = self.sock.recvfrom(65535)
                except socket.timeout:
                    self.retries += 1
                    if self.retries > 5:
                        log(f"[TFTP] timeout block={self.block}, abort"); return False
                    continue
                op = struct.unpack('!H', pkt[:2])[0]
                if op == 4 and len(pkt) >= 4:
                    acked = struct.unpack('!H', pkt[2:4])[0]
                    if acked == self.block:
                        self.retries = 0
                        if len(last) < 4 + self.blksize:  # final block sent
                            dt = time.time() - self.start
                            log(f"[TFTP] DONE {self.peer} block={self.block} {len(self.data)}B in {dt:.1f}s")
                            return True
                        last = self.next_block()
                elif op == 5:
                    log(f"[TFTP] client ERROR: {pkt[4:].split(b'\\x00')[0]!r}")
                    return False
        finally:
            try: self.sock.settimeout(None)   # restore blocking for the shared listener
            except OSError: pass

def looks_tftp(pkt):
    if len(pkt) < 4: return False
    op = struct.unpack('!H', pkt[:2])[0]
    return op in (1, 2, 3, 4, 5, 6)

def handle_rrq(sock, pkt, peer, root, mode_strict=True):
    parts = pkt[2:].split(b'\x00')
    fname = parts[0].decode('latin1')
    mode = parts[1].decode('latin1') if len(parts) > 1 else '?'
    opts = {}
    rest = parts[2:]
    for i in range(0, len(rest) - 1, 2):
        opts[rest[i].decode('latin1').lower()] = rest[i+1].decode('latin1')
    log(f"[RRQ] {peer} file={fname!r} mode={mode!r} opts={opts} raw={pkt.hex()[:120]}")
    root_abs = os.path.abspath(root)
    path = os.path.realpath(os.path.join(root_abs, fname))
    if (os.path.commonpath([root_abs, path]) != root_abs) or not os.path.isfile(path):
        log(f"[RRQ] 404 {fname}")
        sock.sendto(struct.pack('!HH', 5, 1) + b'File not found\x00', peer)
        return
    blksize = min(max(int(opts.get('blksize', 512)), 8), 1468)
    timeout = min(max(float(opts.get('timeout', 1)), 1), 60)
    tsize = os.path.getsize(path)
    if opts:
        ack_opts = b''
        for k in ('blksize', 'timeout', 'tsize'):  # windowsize intentionally not echoed (window=1)
            if k in opts:
                v = str(tsize) if k == 'tsize' else (str(blksize) if k == 'blksize' else (str(int(timeout)) if k == 'timeout' else opts[k]))
                ack_opts += f'{k}\x00{v}\x00'.encode()
        sock.sendto(struct.pack('!H', 6) + ack_opts, peer)
        log(f"[OACK] {ack_opts!r}")
        # RFC2347: client must ACK the OACK (block 0) before first DATA
        for _ in range(5):
            try:
                sock.settimeout(timeout)
                pkt, _ = sock.recvfrom(2048)
                if struct.unpack('!H', pkt[:2])[0] == 4:
                    break
                if struct.unpack('!H', pkt[:2])[0] == 5:
                    return
            except socket.timeout:
                sock.sendto(struct.pack('!H', 6) + ack_opts, peer)
        sock.settimeout(None)
    t = Transfer(path, blksize, sock, peer, timeout)
    t.run()

def watcher(sock, root):
    """raw loop: parse TFTP RRQ/WRQ, log everything else (Sahara etc.)"""
    while True:
        pkt, peer = sock.recvfrom(65535)
        if looks_tftp(pkt):
            op = struct.unpack('!H', pkt[:2])[0]
            if op == 1:
                try:
                    handle_rrq(sock, pkt, peer, root)
                except Exception as e:
                    log(f"[!] rrq error {e!r}")
            elif op == 2:
                log(f"[WRQ] {peer} {pkt.hex()[:120]} (not supported, error)")
                sock.sendto(struct.pack('!HH', 5, 0) + b'no wrq\x00', peer)
            else:
                log(f"[TFTP op{op}] {peer} {pkt.hex()[:80]}")
        else:
            log(f"[UDP-NON-TFTP] {peer} len={len(pkt)} hex={pkt.hex()[:200]}")
            if len(pkt) >= 8:
                le = struct.unpack('<I', pkt[4:8])[0] if len(pkt) >= 8 else -1
                log(f"[UDP-NON-TFTP] maybe-sahara cmd_le=0x{le:x} (HELLO=0x01)" if le < 0x40 else "")

def selftest():
    import tempfile
    root = tempfile.mkdtemp()
    open(os.path.join(root, 'armprg.bin'), 'wb').write(secrets.token_bytes(10000))
    port = 1069
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    threading.Thread(target=watcher, args=(srv, root), daemon=True).start()
    time.sleep(0.2)
    # minimal client RRQ with blksize
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(3)
    c.sendto(struct.pack('!H', 1) + b'armprg.bin\x00octet\x00blksize\x001024\x00tsize\x000\x00', ('127.0.0.1', port))
    got, _ = c.recvfrom(2048)
    assert struct.unpack('!H', got[:2])[0] == 6, "expected OACK"
    log(f"[selftest] OACK ok: {got}")
    c.sendto(struct.pack('!HH', 4, 0), ('127.0.0.1', port))   # ACK the OACK
    data = b''
    blk = 0
    while True:
        pkt, _ = c.recvfrom(2048)
        op, b = struct.unpack('!HH', pkt[:4])
        assert op == 3
        if b == blk + 1:          # ignore retransmitted duplicates
            data += pkt[4:]
            blk = b
        c.sendto(struct.pack('!HH', 4, b), ('127.0.0.1', port))
        if len(pkt) < 4 + 1024: break
    assert data == open(os.path.join(root, 'armprg.bin'), 'rb').read(), "content mismatch"
    log(f"[selftest] transferred {len(data)} bytes in {blk} blocks OK")

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=69)
    ap.add_argument('--root', default='UPDATE')
    ap.add_argument('--log', default='tftp-traffic.log')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    if a.selftest:
        selftest(); sys.exit(0)
    LOGF = open(a.log, 'a')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((a.bind, a.port))
    log(f"[factory_tftp] listening {a.bind}:{a.port} root={os.path.abspath(a.root)}")
    try:
        watcher(sock, os.path.abspath(a.root))
    except PermissionError:
        print("need root/CAP_NET_BIND_SERVICE for port 69 (or use --port 1069)", file=sys.stderr); raise
