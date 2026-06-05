# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import argparse
import subprocess
import time
from typing import Optional

from ssh_utils import check_ssh, run_ssh
from flash.context import log, say, poll_until, get_link_state
from platform_utils import configure_interface_ip, remove_interface_ip
from conwrt.flash_utils import _detect_ssh_key_path
from conwrt.device_inventory import auto_detect_interface


def cmd_reset(args: argparse.Namespace) -> int:
    """Factory reset an OpenWrt router via SSH firstboot or failsafe mode."""
    ip = args.ip

    # --- resolve SSH key ---
    ssh_key = args.ssh_key if args.ssh_key else _detect_ssh_key_path()

    # --- detect interface ---
    interface = args.interface or auto_detect_interface()
    if not interface:
        log("ERROR: No ethernet interface detected. Use --interface to specify.")
        return 1

    # --- try SSH first ---
    if check_ssh(ip):
        log(f"SSH available at {ip}. Running firstboot directly.")
        if args.dry_run:
            print(f"  ssh root@{ip} 'firstboot -y && reboot'")
            return 0
        r = run_ssh(ip, "firstboot -y && reboot", key=ssh_key, timeout=15)
        if r.returncode != 0 and not r.stdout and not r.stderr:
            # Connection closed by remote — expected during reboot
            pass
        elif r.returncode != 0 and ("Connection refused" in r.stderr or "timed out" in r.stderr.lower()):
            log(f"firstboot failed: {r.stderr.strip()}")
            return 1
        log("Factory reset initiated. Device will reboot to defaults.")
        if not args.no_voice:
            say("Factory reset initiated. The router will reboot to default settings.")
        return 0

    # --- failsafe path ---
    log(f"SSH not available at {ip}. Entering failsafe mode.")
    if not args.no_voice:
        say("Cannot reach the router via SSH. We will use OpenWrt failsafe mode.")
        say("I need you to power cycle the router. Unplug the power cable now.")

    log("Waiting for link down...")
    link_was_up = get_link_state(interface)
    if link_was_up:
        poll_until(lambda: not get_link_state(interface), timeout=30, interval=0.5)

    if not args.no_voice:
        say("Power disconnected. Now plug in the power cable.")

    # --- start tcpdump monitoring ---
    local_mac = ""
    try:
        mac_r = subprocess.run(
            ["ifconfig", interface], capture_output=True, text=True, check=False,
        )
        mac_line = [l for l in mac_r.stdout.splitlines() if "ether " in l]
        local_mac = mac_line[0].split("ether ")[1].split()[0] if mac_line else ""
    except Exception:
        pass

    tcpdump_filter = ["not", "ether", "src", local_mac] if local_mac else []
    tcpdump_proc: Optional[subprocess.Popen] = None
    boot_detected = False

    try:
        tcpdump_proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", interface, "-n", "-A",
             "--immediate-mode", "-l", "port", "4919", "and", "udp"]
            + tcpdump_filter,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        if args.dry_run:
            log(f"  (dry run) would monitor: sudo tcpdump -i {interface} -n -A --immediate-mode -l port 4919 and udp")
            return 0

        if tcpdump_proc.stdout is not None:
            for line in tcpdump_proc.stdout:
                line = line.strip()
                if not line or line.startswith("tcpdump:"):
                    continue
                if not boot_detected and "Please press button" in line:
                    log("FAILSAFE PROMPT DETECTED")
                    if not args.no_voice:
                        say("PRESS AND HOLD THE RESET BUTTON NOW. Hold for 2 seconds then release.")
                    boot_detected = True
                    failsafe_deadline = time.time() + 5
                    continue
                if boot_detected and time.time() >= failsafe_deadline:
                    break
    except Exception as exc:
        log(f"tcpdump error: {exc}")
    finally:
        if tcpdump_proc is not None:
            tcpdump_proc.terminate()
            try:
                tcpdump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tcpdump_proc.kill()

    if not boot_detected:
        log("No boot packet detected. The device may not have powered on yet.")
        if not args.no_voice:
            say("No boot detected. Please try again.")
        return 1

    # --- wait then check failsafe ---
    log("Waiting 10 seconds for failsafe mode to activate...")
    time.sleep(10)

    ping_r = subprocess.run(
        ["ping", "-c", "3", "-t", "2", ip],
        capture_output=True, text=True, check=False,
    )
    if ping_r.returncode != 0:
        log("Failsafe mode not detected (no ping response).")
        if not args.no_voice:
            say("Failsafe mode not detected. Try power cycling again and press reset sooner.")
        return 1

    log("Failsafe mode detected. Configuring interface and connecting via SSH.")
    if not args.no_voice:
        say("Failsafe mode detected. Connecting via SSH.")

    client_ip = "192.168.1.2"
    configured = configure_interface_ip(interface, client_ip, "24")
    if not configured:
        log(f"ERROR: Could not configure {interface} with IP {client_ip}. "
            f"Run 'sudo -v' to cache sudo credentials, then retry.")
        return 1

    r = run_ssh(ip, "firstboot -y && reboot", key=ssh_key, timeout=15)
    if r.returncode != 0 and (r.stdout or r.stderr):
        log(f"firstboot via failsafe SSH failed: {r.stderr.strip()}")
        return 1

    log("Factory reset complete. The router will reboot with default settings.")
    if not args.no_voice:
        say("Factory reset complete. The router will reboot with default settings.")

    remove_interface_ip(interface, client_ip, "24")
    return 0
