"""capture command — stream remote tcpdump from the probe port to a local pcap.

Core implementation validated on real hardware (x1860, MT7621/DSA):
  - tcpdump -i <iface> -s 0 -U -w -  produces clean pcap via stdout
  - Killing local ssh cleanly kills remote tcpdump (broken pipe)
  - timeout command does NOT exist on OpenWrt — must use client-side termination
  - tcpdump may be missing — detect and print install instructions
"""

from __future__ import annotations

import argparse
import shlex
import signal
import sys
import time
from pathlib import Path

from fieldlab.transport import Host, check_ssh, check_tool, stream_remote
from fieldlab.rundir import FieldLabRun


def _build_tcpdump_command(probe_if: str, filter_expr: str | None = None) -> str:
    """Build the remote tcpdump command for pcap streaming.

    Flags:
      -U     packet-buffered (flush after each packet — critical for streaming)
      -s 0   full snaplen (capture entire packets)
      -w -   write pcap to stdout
    """
    cmd = f"tcpdump -i {shlex.quote(probe_if)} -s 0 -U -w -"
    if filter_expr:
        cmd += f" {shlex.quote(filter_expr)}"
    cmd += " 2>/dev/null"
    return cmd


def _detect_probe_interface(host: Host) -> str | None:
    """Auto-detect the probe interface via UCI."""
    from fieldlab.transport import run_remote
    result = run_remote(host, "uci get network.wan.device 2>/dev/null", timeout=8)
    dev = result.stdout.strip()
    if dev and dev != "none" and result.returncode == 0:
        return dev
    return None


def _stream_to_output(proc, out_path: str, duration: int) -> int:
    """Read from proc.stdout, write to file or stdout, handle timeout + signals.

    Returns the process exit code.
    """
    # Open output target
    if out_path == "-":
        out_file = sys.stdout.buffer  # type: ignore[assignment]
        close_on_done = False
    else:
        out_file = open(out_path, "wb")  # type: ignore[assignment]
        close_on_done = True

    # Install signal handler for clean Ctrl-C
    user_interrupted = False
    duration_reached = False

    def _on_signal(signum, _frame):
        nonlocal user_interrupted
        user_interrupted = True
        proc.terminate()

    old_int = signal.signal(signal.SIGINT, _on_signal)
    old_term = signal.signal(signal.SIGTERM, _on_signal)

    start = time.monotonic()
    bytes_written = 0
    try:
        while True:
            # Check duration timeout
            if duration > 0 and (time.monotonic() - start) >= duration:
                duration_reached = True
                print(f"\n[+] Duration {duration}s reached, stopping...", file=sys.stderr)
                proc.terminate()
                break

            chunk = proc.stdout.read(65536)  # type: ignore[union-attr]
            if not chunk:
                break  # EOF — remote process ended
            out_file.write(chunk)  # type: ignore[union-attr]
            bytes_written += len(chunk)
            # Flush for real-time output (critical for stdout piping)
            try:
                out_file.flush()  # type: ignore[union-attr]
            except BrokenPipeError:
                break

    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        user_interrupted = True
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        if close_on_done:
            out_file.close()  # type: ignore[union-attr]

    if user_interrupted:
        print(f"[+] Capture interrupted by user", file=sys.stderr)
    elif duration_reached:
        pass  # already printed above
    print(f"[+] Captured {bytes_written} bytes", file=sys.stderr)
    return proc.returncode if proc.returncode is not None else 0


def cmd_capture(args: argparse.Namespace, host: Host) -> int:
    """Stream a remote tcpdump capture to a local pcap file or stdout."""
    # Resolve probe interface
    probe_if = args.probe_if
    if not probe_if:
        probe_if = _detect_probe_interface(host)
    if not probe_if:
        print("[!] Could not detect probe interface. Use --probe-if to specify it.",
              file=sys.stderr)
        print("    Run 'fieldlab inspect' to see available interfaces.", file=sys.stderr)
        return 1

    print(f"[+] Field router: {host}", file=sys.stderr)
    print(f"[+] Probe interface: {probe_if}", file=sys.stderr)

    # Check connectivity
    if not check_ssh(host):
        print(f"[!] Cannot SSH to {host}.", file=sys.stderr)
        return 1

    # Check tcpdump availability
    if not check_tool(host, "tcpdump"):
        print("[!] tcpdump is not installed on the field router.", file=sys.stderr)
        print("    Install it with (from a machine with internet):", file=sys.stderr)
        print(f"      scp -O tcpdump_*.ipk libpcap1_*.ipk {host}:/tmp/", file=sys.stderr)
        print(f"      ssh {host} 'opkg install /tmp/libpcap1_*.ipk && opkg install /tmp/tcpdump_*.ipk'", file=sys.stderr)
        print("    Or if the router has internet:", file=sys.stderr)
        print(f"      ssh {host} 'opkg update && opkg install tcpdump'", file=sys.stderr)
        return 1

    # Resolve output path
    out_path = args.out
    session = args.session
    run = None
    if session:
        run = FieldLabRun(session)
    elif out_path and out_path != "-":
        run = FieldLabRun.create()
    elif not out_path:
        run = FieldLabRun.create()

    if not out_path:
        out_path = str(run.captures_dir / f"probe-{probe_if}.pcap")  # type: ignore[union-attr]
        run.captures_dir.mkdir(parents=True, exist_ok=True)  # type: ignore[union-attr]

    duration = args.duration
    filter_expr = args.filter

    if out_path == "-":
        print(f"[+] Streaming to stdout (pipe to: tcpdump -r - -nn -e)", file=sys.stderr)
    else:
        print(f"[+] Output: {out_path}", file=sys.stderr)
    if duration > 0:
        print(f"[+] Duration: {duration}s", file=sys.stderr)
    else:
        print(f"[+] Duration: indefinite (Ctrl-C to stop)", file=sys.stderr)
    if filter_expr:
        print(f"[+] Filter: {filter_expr}", file=sys.stderr)

    tcpdump_cmd = _build_tcpdump_command(probe_if, filter_expr)
    print(f"[+] Starting capture...", file=sys.stderr)

    proc = stream_remote(host, tcpdump_cmd)

    exit_code = _stream_to_output(proc, out_path, duration)

    # Record in manifest
    if run:
        run.record_command(
            "capture",
            probe_interface=probe_if,
            output=out_path,
            duration=duration,
            bytes_written=Path(out_path).stat().st_size if out_path != "-" else 0,
        )

    if out_path != "-":
        size = Path(out_path).stat().st_size
        if size == 0:
            print(f"[!] Warning: 0-byte pcap — no packets captured.", file=sys.stderr)
            print(f"    Check that the probe interface '{probe_if}' has a connected device.",
                  file=sys.stderr)
        else:
            print(f"[+] Done. {size} bytes → {out_path}", file=sys.stderr)
            print(f"    Read with: tcpdump -r {out_path} -nn -e", file=sys.stderr)

    return exit_code if exit_code is not None else 0
