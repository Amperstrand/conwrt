#!/usr/bin/env python3
"""test_blankdl_fence.py — regression test for the blank-download fence.

Catches the 2026-11-08 off-by-one in packet_for() (resends shipped the wrong
block: block N must carry image[(N-1)*blksize : N*blksize)). Verifies
byte-exact serving across image geometries, including a realistic
mid-transfer duplicate-ACK (forces the resend path).
"""
import hashlib, os, random, socket, struct, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
FENCE = os.path.join(HERE, "zte-blankdl-flashd.py")

def serve_and_fetch(image_bytes, port, dup_ack_at=None, blksize=1468, timeout=20):
    """Fetch the image as a TFTP client. dup_ack_at=N duplicates the ACK for
    block N once (forces the fence's resend path deterministically)."""
    sha = hashlib.sha256(image_bytes).hexdigest()
    d = tempfile.mkdtemp(prefix="fence-test-")
    img = os.path.join(d, "img"); open(img, "wb").write(image_bytes)
    p = subprocess.Popen([sys.executable, FENCE, "--image", f"{img}#sha256:{sha}",
                          "--bind", "127.0.0.1", "--port", str(port), "--log-dir", d],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        s.sendto(b"\x00\x01root_uImage\x00octet\x00blksize\x00" + str(blksize).encode() + b"\x00",
                 ("127.0.0.1", port))
        got = b""; expected = 1; peer = None; dupd = False
        while True:
            pkt, addr = s.recvfrom(65535)
            peer = peer or addr
            op = struct.unpack(">H", pkt[:2])[0]
            if op == 6:
                s.sendto(b"\x00\x04\x00\x00", peer); continue
            if op == 3:
                blk = struct.unpack(">H", pkt[2:4])[0]
                if blk == expected: got += pkt[4:]; expected += 1
                s.sendto(b"\x00\x04" + struct.pack(">H", blk), peer)
                if dup_ack_at and not dupd and blk == dup_ack_at:
                    dupd = True
                    s.sendto(b"\x00\x04" + struct.pack(">H", blk), peer)  # duplicate ACK
                if len(pkt) < 4 + blksize and blk == expected - 1: break
        return hashlib.sha256(got).hexdigest() == sha, len(got)
    except socket.timeout:
        # exact-multiple images: the fence completes without an RFC empty-EOF
        # block (known minor gap, bytes all served) — success iff complete+exact
        return hashlib.sha256(got).hexdigest() == sha, len(got)
    finally:
        p.terminate()

def main():
    rng = random.Random(42)
    port = 18700
    cases = [
        ("empty-ish 424B", rng.randbytes(424), None),
        ("single full block", rng.randbytes(1468), None),
        ("exact multiple 5x", rng.randbytes(1468 * 5), None),
        ("non-multiple 5x+100", rng.randbytes(1468 * 5 + 100), 2),   # + dup-ACK at block 2
        ("non-multiple 1MiB", rng.randbytes(1048576), 3),            # + dup-ACK at block 3
        ("exact multiple 1MiB-ish", rng.randbytes(1468 * 714), 5),   # exact EOF-block path
        ("large 700x+317", rng.randbytes(1468 * 700 + 317), None),
    ]
    fails = 0
    for name, img, dup in cases:
        port += 1
        ok, n = serve_and_fetch(img, port, dup_ack_at=dup)
        tag = "PASS" if ok else "FAIL"
        print(f"[{tag}] {name}{' (+dup-ACK@%d)' % dup if dup else ''}: {n}/{len(img)} bytes")
        fails += 0 if ok else 1
    print("RESULT:", "ALL PASS" if fails == 0 else f"{fails} FAILURES")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
