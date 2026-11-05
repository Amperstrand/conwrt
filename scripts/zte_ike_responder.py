#!/usr/bin/env python3
"""
ZTE CNDMS IKE (ISAKMP vendor exchange 0xF3) responder.
Listens on UDP 500, mirrors/accepts the ZAS updater's phase-1 opener,
handles standard Main Mode (2) / Aggressive (4) best-effort.
Logs every packet hex for species notes.

Usage:  ike_responder.py [--bind 192.168.82.3] [--port 500] [--logdir DIR]
Test:   ike_responder.py --selftest   (replays /tmp/opencode/opener.hex locally)
"""
import argparse, hashlib, os, socket, struct, sys, time, secrets

# ---------------- ISAKMP helpers ----------------
def payload(nxt, body):
    return struct.pack('!BBH', nxt, 0, len(body) + 4) + body

def header(icki, ickr, np, xchg, flags, msgid, body):
    return (icki + ickr + bytes([np, 0x10, xchg, flags])
            + struct.pack('!II', msgid, len(body) + 28) + body)

def parse_payloads(data):
    """yield (type, hdr_off, body_off, plen, next, body) following the chain"""
    off = 28
    ptype = data[16]
    while off + 4 <= len(data):
        nxt, _res, plen = struct.unpack('!BBH', data[off:off+4])
        if plen < 4 or off + plen > len(data):
            break
        yield (ptype, off, off + 4, plen, nxt, data[off+4:off+plen])
        ptype = nxt
        off += plen
        if ptype == 0:
            break

def sha1(b):
    return hashlib.sha1(b).digest()

# ---------------- ECP-256 KE (mirror client's raw X||Y encoding) ----------------
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    def ecp256_keypair():
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)  # 04||X||Y
        return priv, pub[1:]  # raw X||Y 64 bytes like the client sends
    def ecp256_shared(priv, peer64):
        peer = b'\x04' + peer64
        peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer)
        return priv.exchange(ec.ECDH(), peer_pub)
except Exception as _e:  # pragma: no cover
    ecp256_keypair = ecp256_shared = None

VID_RFC3947 = bytes.fromhex('4a131c81070358455c5728f20e95452f')
VID_FRAG    = bytes.fromhex('4048b7d56ebce88525e7de7f00d6c2d3')

class Session:
    def __init__(self, icki, peer):
        self.icki = icki
        self.ickr = secrets.token_bytes(8)
        self.peer = peer
        self.dh_priv, self.ke = ecp256_keypair()
        self.nonce = secrets.token_bytes(48)
        self.last_tx = None
        self.stage = 0

def nat_d(icky_i, icky_r, ip, port):
    return sha1(icky_i + icky_r + socket.inet_aton(ip) + struct.pack('!H', port))

def build_f3_response(sess, req, my_ip, my_port):
    """Mirror-accept the vendor 0xF3 opener: echo SA (acceptance), our KE/Nr,
    echo VIDs, correct NAT-Ds."""
    ps = list(parse_payloads(req))
    sa_body = next((b for t, _, _, _, _, b in ps if t == 1), None)
    vid_echos = []
    for t, _, _, _, _, b in ps:
        if t == 13 and b[:16] in (VID_RFC3947, VID_FRAG):
            vid_echos.append(b[:16])
    if not vid_echos:
        vid_echos = [VID_RFC3947]
    peer_ip, peer_port = sess.peer[0], sess.peer[1]
    # NAT-D: initiator's hash first (their ip), then ours — as client sent them
    natd_peer = nat_d(sess.icki, sess.ickr, peer_ip, peer_port)
    natd_me   = nat_d(sess.icki, sess.ickr, my_ip, my_port)
    # chain: 0x85 -> SA -> 0x87 -> NONCE -> VID[..] -> NATD(peer) -> NATD(me) -> KE(last)
    p85   = payload(0x01, bytes.fromhex('00000000'))
    pSA   = payload(0x87, sa_body if sa_body else b'')
    p87   = payload(0x0a, bytes.fromhex('00030000'))
    pNON  = payload(0x0d if vid_echos else 0x14, sess.nonce)
    vidps = []
    for i, v in enumerate(vid_echos):
        nxt = 0x14 if i == len(vid_echos) - 1 else 0x0d
        vidps.append(payload(nxt, v))
    pNAT1 = payload(0x14, natd_peer)
    pNAT2 = payload(0x04, natd_me)
    pKE   = payload(0x00, sess.ke)
    body = p85 + pSA + p87 + pNON + b''.join(vidps) + pNAT1 + pNAT2 + pKE
    return header(sess.icki, sess.ickr, 0x85, 0xF3, 0x00, 0, body)

def build_mainmode_sa_response(sess, req):
    ps = list(parse_payloads(req))
    sa_body = next((b for t, _, _, _, _, b in ps if t == 1), None)
    if sa_body is None:
        return None
    body = payload(0x00, sa_body)  # echo entire SA = accept first transform
    return header(sess.icki, sess.ickr, 0x01, 0x02, 0x00, 0, body)

def build_mm2_response(sess, req):
    """Main mode msg2-equivalent (they sent KE+Ni): reply KE+Nr"""
    pKE  = payload(0x0a, sess.ke)
    pNON = payload(0x00, sess.nonce)
    return header(sess.icki, sess.ickr, 0x04, 0x02, 0x00, 0, pKE + pNON)

class Responder:
    def __init__(self, bind_ip, port, logdir):
        self.bind_ip, self.port, self.logdir = bind_ip, port, logdir
        os.makedirs(logdir, exist_ok=True)
        self.logf = open(os.path.join(logdir, 'ike-traffic.log'), 'a', buffering=1)
        self.sessions = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_ip, port))

    def log(self, tag, data, peer):
        ts = time.strftime('%H:%M:%S') + '.%03d' % (int(time.time()*1000) % 1000)
        line = f"{ts} {tag} {peer[0]}:{peer[1]} len={len(data)} {data.hex()}"
        print(line[:200] + ('...' if len(line) > 200 else ''))
        self.logf.write(line + '\n')
        fname = f"{int(time.time()*1000)}_{tag}.hex"
        with open(os.path.join(self.logdir, fname), 'w') as f:
            f.write(data.hex())

    def run(self):
        print(f"[ike_responder] listening on {self.bind_ip}:{self.port}, logs in {self.logdir}")
        while True:
            data, peer = self.sock.recvfrom(4096)
            self.log('RX', data, peer)
            if len(data) < 28:
                continue
            if data[:1] == b'\xff':  # NAT keepalive
                continue
            try:
                resp = self.handle(data, peer)
            except Exception as e:
                print(f"[!] handle error: {e!r}")
                continue
            if resp:
                self.log('TX', resp, peer)
                self.sock.sendto(resp, peer)

    def handle(self, data, peer):
        icki, ickr = data[:8], data[8:16]
        np_, ver, xchg, flags = data[16], data[17], data[18], data[19]
        msgid = struct.unpack('!I', data[20:24])[0]
        key = icki
        sess = self.sessions.get(key)
        if sess is None or ickr == b'\x00'*8:
            sess = Session(icki, peer)
            self.sessions[key] = sess
        # retransmission of same opener: resend cached response
        if sess.last_tx is not None and xchg == 0xF3 and msgid == 0 and flags == 0:
            return sess.last_tx
        if xchg == 0xF3 and msgid == 0 and flags == 0x00:
            resp = build_f3_response(sess, data, self.bind_ip, self.port)
            sess.stage = 1
        elif xchg == 0x02 and flags == 0x00 and np_ == 0x01:  # main mode msg1 (SA)
            resp = build_mainmode_sa_response(sess, data)
        elif xchg == 0x02 and flags == 0x00:  # main mode msg2-ish (KE+Ni)
            resp = build_mm2_response(sess, data)
        elif xchg == 0x04:  # aggressive
            if np_ == 0x01:
                resp = build_mainmode_sa_response(sess, data)
            else:
                resp = build_f3_response(sess, data, self.bind_ip, self.port)
        else:
            print(f"[?] unhandled: xchg=0x{xchg:02x} np=0x{np_:02x} flags=0x{flags:02x} msgid={msgid} "
                  f"— logging only (encrypted/vendor phase?)")
            self.logf.write(f"# unhandled xchg=0x{xchg:02x} np=0x{np_:02x} flags=0x{flags:02x} msgid={msgid}\n")
            return None
        sess.last_tx = resp
        return resp

def selftest():
    """Replay the captured opener at ourselves through loopback."""
    opener = bytes.fromhex(open('/tmp/opencode/opener.hex').read().strip())
    r = Responder('127.0.0.1', 15000, '/tmp/opencode/ztsuf/work/ike-selftest')
    import threading
    threading.Thread(target=lambda: r.run() if False else r._serve_once(opener), daemon=True).start()
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(2)
    c.sendto(opener, ('127.0.0.1', 15000))
    try:
        resp, _ = c.recvfrom(4096)
        print(f"[selftest] got {len(resp)}-byte response:")
        print(resp.hex())
        # sanity: header fields
        assert resp[:8] == opener[:8], "I-cookie mismatch"
        assert resp[8:16] != b'\x00'*8, "R-cookie zero"
        assert resp[18] == 0xF3
        ln = struct.unpack('!I', resp[24:28])[0]
        assert ln == len(resp), f"length mismatch {ln} != {len(resp)}"
        types = [t for t, *_ in parse_payloads(resp)]
        print(f"[selftest] payload chain: {[hex(t) for t in types]} OK")
    except socket.timeout:
        print("[selftest] FAIL: no response")

# small helper for selftest: serve exactly one packet
def _serve_once(self, opener):
    data, peer = self.sock.recvfrom(4096)
    self.log('RX', data, peer)
    resp = self.handle(data, peer)
    if resp:
        self.log('TX', resp, peer)
        self.sock.sendto(resp, peer)

Responder._serve_once = _serve_once

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--bind', default='192.168.82.3')
    ap.add_argument('--port', type=int, default=500)
    ap.add_argument('--logdir', default='/tmp/opencode/ztsuf/work/ike-logs')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    if a.selftest:
        selftest()
    else:
        Responder(a.bind, a.port, a.logdir).run()
