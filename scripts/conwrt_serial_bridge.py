#!/usr/bin/env python3
"""conwrt-serial-bridge — expose a router's UART console as a local TCP port.

Bridges a serial console that lives on a *listener* OpenWrt router (reached over
SSH, optionally through a ProxyJump bastion such as the bench switch) to a local
TCP port that labgrid's NetworkSerialPort / SerialDriver can consume.

    DUT UART --3-wire--> listener AP /dev/ttyMSM0
                            ^  ssh (via switch)
                            |  stdout/stdin stream
    labgrid SerialDriver --TCP--> this bridge (127.0.0.1:PORT)

One bridge process serves ONE serial pair on ONE TCP port. Auto-reconnects the
SSH stream with backoff; clients are dropped on reconnect (stale byte stream).

The SSH channel runs a remote shell that:
  * comments the tty's console-getty line out of /etc/inittab and kills the
    getty, so the bridge owns the tty (idempotent); the getty is restored
    ONLY when the remote script is killed intentionally (TERM/INT) — never
    on stream drops, where the reconnect's free_tty would race the
    respawned getty and silence the console,
  * `cat`s the tty to stdout (console RX) and `cat`s a FIFO into the tty
    (console TX) so connected clients can both read and write.

No external deps (stdlib only) so it runs in the exporter host's labgrid venv
or system python. BusyBox-safe remote shell (no stty needed — the AP3915i
kernel console is already 115200 8N1; no setsid requirement beyond the stream).
"""

from __future__ import annotations

import argparse
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time

STOP = threading.Event()

# Remote-side shell. Runs ON the listener router. $TTY is the console device.
# Frees the tty (idempotent, no set -e so one missing file can't abort the
# free step), then streams it both ways. Restores inittab + getty ONLY on
# intentional termination (TERM/INT); the EXIT path (ssh stream dropped ->
# stdin EOF) deliberately does NOT restore: the bridge auto-reconnects and
# re-frees, and a restore there races the respawned getty against the new
# cats (observed wedge 2026-09-23: getty re-armed mid-flight, /bin/login
# took the tty, console delivered 0 bytes).
REMOTE_SH = r"""
TTY="$1"
LOG="${2:-/tmp/conwrt-bridge-target.log}"

free_tty() {
  # BusyBox inittab console ids are device BASENAMES ("ttyMSM0"), never
  # /dev/ paths, and the id starts at column 0 — match with [^#]* (zero or
  # more), not [^#].* (which demands a leading char and never matched: the
  # getty was never actually freed, and its respawn raced the cats for bytes).
  TTYID="${TTY#/dev/}"
  if grep -q "^[^#]*$TTYID" /etc/inittab 2>/dev/null; then
    [ -f /etc/inittab.bak-conwrt ] || cp /etc/inittab /etc/inittab.bak-conwrt 2>/dev/null
    sed -i "s|^\([^#]*$TTYID\)|#\1|" /etc/inittab 2>/dev/null
    kill -HUP 1 2>/dev/null
    sleep 1
  fi
  # kill anything already holding the tty: a console getty (or the /bin/login
  # an askfirst activation leaves behind) OR a stale 'cat $TTY' from a
  # previous bridge run (two readers race for the same bytes).
  for p in $(ps | grep -E "askfirst|getty|login\.sh|/bin/login |cat $TTY" | grep -v grep | awk '{print $1}'); do
    kill "$p" 2>/dev/null
  done
  sleep 1
}

restore_tty() {
  if [ -f /etc/inittab.bak-conwrt ]; then
    cp /etc/inittab.bak-conwrt /etc/inittab 2>/dev/null
    kill -HUP 1 2>/dev/null
  fi
}

free_tty

# FIFO so client input flows INTO the tty (console TX)
FIFO=/tmp/conwrt-bridge-tx.$$
mkfifo "$FIFO" 2>/dev/null
cat "$FIFO" > "$TTY" &
TXPID=$!
# stream tty -> stdout (console RX); 'cat' blocks reading, dies with us
cat "$TTY" &
RXPID=$!

INTENTIONAL=0
on_terminate() {
  INTENTIONAL=1
  restore_tty
  kill $TXPID $RXPID 2>/dev/null
  rm -f "$FIFO"
  exit 0
}
# intentional kill of this shell (e.g. maintenance on the listener): restore
trap on_terminate TERM INT
# stream drop (bridge side closed the channel -> cat EOF -> normal exit):
# reap helpers but do NOT restore the getty (see comment above REMOTE_SH)
trap '[ "$INTENTIONAL" = 1 ] || { kill $TXPID $RXPID 2>/dev/null; rm -f "$FIFO"; }' EXIT
# hold the channel open on stdin, forwarding console TX into the FIFO until
# EOF. A line containing exactly the stop token is the bridge's intentional
# shutdown signal: restore the getty and exit cleanly. The bridge sends it
# BEFORE closing stdin so a deliberate stop never leaves /etc/inittab
# commented and the listener's native console dead.
while IFS= read -r line; do
  if [ "$line" = "__CONWRT_SERIAL_BRIDGE_STOP__" ]; then
    on_terminate
  fi
  printf '%s\n' "$line" > "$FIFO"
done
"""


def log(msg: str) -> None:
    sys.stderr.write(f"[conwrt-serial-bridge {time.strftime('%H:%M:%S')}] {msg}\n")
    sys.stderr.flush()


class SSHStream:
    """One SSH child process carrying the remote tty stream."""

    def __init__(self, target: str, jump: str | None, tty: str, remote_log: str):
        self.target = target
        self.jump = jump
        self.tty = tty
        self.remote_log = remote_log
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        cmd = ["ssh",
               "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
               "-o", "ControlMaster=no",  # each bridge owns its channel
               ]
        if self.jump:
            cmd += ["-J", self.jump]
        cmd += [self.target, f"sh -s -- {self.tty} {self.remote_log}"]
        log(f"ssh stream: {' '.join(cmd)}")
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert self.proc.stdin and self.proc.stdout
        # push the remote script, keep stdin open as the TX/hold channel
        self.proc.stdin.write(REMOTE_SH.encode())
        self.proc.stdin.flush()

    def read(self, n: int = 4096, timeout: float = 1.0) -> bytes:
        """Timeout-bound read so a silent-but-alive stream never wedges the pump."""
        if not self.proc or not self.proc.stdout:
            return b""
        fd = self.proc.stdout.fileno()
        r, _, _ = select.select([fd], [], [], timeout)
        if not r:
            return b""
        try:
            return os.read(fd, n)
        except OSError:
            return b""

    def write(self, data: bytes) -> None:
        assert self.proc and self.proc.stdin
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            # Tell the REMOTE script this is an intentional shutdown so it
            # restores the listener's getty (EOF alone is the stream-drop
            # path, which deliberately does not restore). Give the remote
            # shell a moment to run on_terminate before tearing down ssh.
            try:
                assert self.proc.stdin
                self.proc.stdin.write(b"__CONWRT_SERIAL_BRIDGE_STOP__\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=5)
            except Exception:
                pass
            if self.proc.poll() is None:
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=5)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
        self.proc = None


class Bridge:
    def __init__(self, listen_host: str, listen_port: int, stream: SSHStream):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.stream = stream
        self.client: socket.socket | None = None
        self.client_lock = threading.Lock()

    def _set_client(self, conn: socket.socket | None) -> None:
        with self.client_lock:
            if self.client is not None:
                try:
                    self.client.close()
                except Exception:
                    pass
            self.client = conn

    def _clear_client(self, conn: socket.socket) -> None:
        """Clear the shared slot ONLY if it still holds this handler's own
        socket: after a replacement (_set_client(B) closed A and installed
        B), handler A reaching its finally block must not close B and race
        the fresh connection into an instant disconnect."""
        with self.client_lock:
            if self.client is conn:
                self.client = None
                return
        try:
            conn.close()
        except Exception:
            pass

    def _get_client(self) -> socket.socket | None:
        with self.client_lock:
            return self.client

    def serial_to_client(self) -> None:
        """Pump bytes from the SSH stream to the connected TCP client."""
        rx = 0
        last_report = time.time()
        while not STOP.is_set():
            try:
                if not self.stream.alive():
                    time.sleep(0.2)
                    continue
                data = self.stream.read(4096, timeout=1.0)
                if not data:
                    if not self.stream.alive():
                        continue  # supervise() will reconnect
                    time.sleep(0.05)
                    continue
                rx += len(data)
                conn = self._get_client()
                if conn is not None:
                    try:
                        conn.sendall(data)
                    except OSError:
                        self._set_client(None)
                if time.time() - last_report > 30:
                    log(f"serial pump: {rx} bytes from target so far")
                    last_report = time.time()
            except (OSError, ValueError):
                time.sleep(0.2)
            except Exception as e:  # keep the pump alive
                log(f"serial_to_client: {e!r}")
                time.sleep(0.5)

    def serve_client(self, conn: socket.socket) -> None:
        """Pump bytes from a TCP client into the SSH stream (console TX)."""
        self._set_client(conn)
        log(f"client connected: {conn.getpeername()}")
        try:
            while not STOP.is_set():
                data = conn.recv(4096)
                if not data:
                    break
                if self.stream.alive():
                    try:
                        self.stream.write(data)
                    except (OSError, ValueError):
                        break
        except OSError:
            pass
        finally:
            log("client disconnected")
            self._clear_client(conn)

    def supervise(self) -> None:
        """Keep the SSH stream up; reconnect with backoff."""
        backoff = 2
        while not STOP.is_set():
            if not self.stream.alive():
                log("ssh stream down; (re)connecting")
                # drop the client: its byte stream is stale across a reconnect
                self._set_client(None)
                try:
                    self.stream.start()
                    backoff = 2
                    log("ssh stream up")
                except Exception as e:
                    log(f"connect failed: {e!r}; retry in {backoff}s")
                    STOP.wait(backoff)
                    backoff = min(backoff * 2, 60)
                    continue
            STOP.wait(1.0)

    def run(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_host, self.listen_port))
        srv.listen(2)
        srv.settimeout(1.0)
        log(f"listening on {self.listen_host}:{self.listen_port}")

        threading.Thread(target=self.supervise, daemon=True).start()
        threading.Thread(target=self.serial_to_client, daemon=True).start()

        try:
            while not STOP.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self.serve_client, args=(conn,), daemon=True).start()
        finally:
            STOP.set()
            self.stream.stop()
            srv.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Bridge a router UART console (via SSH) to a TCP port.")
    ap.add_argument("--target", required=True, help="SSH target of the LISTENER router (e.g. root@192.168.104.51)")
    ap.add_argument("--jump", default=None, help="SSH ProxyJump bastion (e.g. root@192.168.13.2)")
    ap.add_argument("--tty", default="/dev/ttyMSM0", help="console device on the listener")
    ap.add_argument("--remote-log", default="/tmp/conwrt-bridge-target.log", help="unused side-channel log name on listener")
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, required=True)
    args = ap.parse_args()

    def _sig(_s, _f):
        STOP.set()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    stream = SSHStream(args.target, args.jump, args.tty, args.remote_log)
    Bridge(args.listen_host, args.listen_port, stream).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
