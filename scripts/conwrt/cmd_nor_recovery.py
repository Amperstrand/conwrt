# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import argparse
import os
import subprocess
import sys
import time
import urllib.request

from model_loader import load_model
from ssh_utils import check_ssh, run_ssh, ssh_cmd
from flash.context import DEFAULT_IP, log, say, poll_until, sha256_file
from conwrt.flash_utils import _detect_ssh_key_path


def cmd_setup_nor_recovery(args: argparse.Namespace) -> int:
    """Set up NOR flash as a recovery OpenWrt partition on dual-flash devices."""
    model_id = args.model_id

    # Load model JSON
    try:
        model = load_model(model_id)
    except FileNotFoundError:
        print(f"ERROR: Model '{model_id}' not found in models/ directory.", file=sys.stderr)
        print("Use 'conwrt list' to see available models.", file=sys.stderr)
        return 1

    nor = model.get("nor_recovery")
    if not nor:
        print(f"ERROR: Model '{model_id}' does not have a 'nor_recovery' section.", file=sys.stderr)
        print("This device may not support dual-flash recovery setup.", file=sys.stderr)
        return 1

    # Resolve IP
    default_ip = model.get("openwrt", {}).get("default_ip", DEFAULT_IP)
    ip = args.ip or default_ip

    # Safety check: --i-want-a-brick required unless --dry-run
    dry_run = args.dry_run
    if not dry_run and not args.i_want_a_brick:
        print("ERROR: NOR recovery involves flashing U-Boot (mtd0) which can brick the device.", file=sys.stderr)
        print("Add --i-want-a-brick to acknowledge this risk, or use --dry-run.", file=sys.stderr)
        return 1

    skip_uboot = args.skip_uboot
    no_voice = args.no_voice

    def _say(msg: str) -> None:
        if not no_voice:
            say(msg)

    uboot_cfg = nor.get("uboot_upgrade", {})
    nor_fw_cfg = nor.get("nor_firmware", {})
    boot_env_cfg = nor.get("boot_env", {})
    requires_kmod = nor.get("requires_kmod_mtd_rw", False)
    mtd_rw_param = nor.get("mtd_rw_module_param", "")

    # Print header
    log(f"NOR Recovery Setup — {model.get('vendor', '?')} {model.get('description', model_id)}")
    log(f"Router IP: {ip}")
    if dry_run:
        log("DRY RUN — no changes will be written to the router")
    if skip_uboot:
        log("Skipping U-Boot upgrade (--skip-uboot)")
    print()

    # Step 1: Verify SSH access
    log("Step 1: Verifying SSH access...")
    ssh_key = _detect_ssh_key_path()
    if not ssh_key:
        print("ERROR: No SSH private key found. Set [ssh].key in config.toml or install ~/.ssh/id_ed25519 or ~/.ssh/id_rsa.", file=sys.stderr)
        return 1

    try:
        r = subprocess.run(
            ssh_cmd(ip, "echo SSH_OK", key=ssh_key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"ERROR: SSH connection to {ip} timed out.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: SSH connection to {ip} failed: {exc}", file=sys.stderr)
        return 1

    if "SSH_OK" not in r.stdout:
        print(f"ERROR: Cannot reach router via SSH at {ip}.", file=sys.stderr)
        if r.stderr:
            print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
        return 1
    log("SSH access OK")

    # Step 2: Verify correct model (check board name)
    log("Step 2: Verifying device model...")
    try:
        r = subprocess.run(
            ssh_cmd(ip, "cat /tmp/sysinfo/board_name", key=ssh_key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
    except OSError as exc:
        print(f"ERROR: Failed to check board name: {exc}", file=sys.stderr)
        return 1

    board_name = r.stdout.strip()
    expected_device = model.get("openwrt", {}).get("device", "")
    if expected_device and board_name != expected_device:
        print("WARNING: Board name mismatch!", file=sys.stderr)
        print(f"  Expected: {expected_device}", file=sys.stderr)
        print(f"  Got:      {board_name}", file=sys.stderr)
        if not dry_run:
            print("Aborting. Use a different --model-id or verify the device.", file=sys.stderr)
            return 1
    log(f"Board: {board_name} — matches model")

    # Step 3: nor_recovery section already checked above
    log("Step 3: Model has nor_recovery section ✓")

    if dry_run:
        print()
        log("=== DRY RUN — would perform the following steps ===")
        if not skip_uboot and uboot_cfg:
            log(f"  4. Download U-Boot from: {uboot_cfg.get('url', '?')}")
            log(f"     Expected SHA256: {uboot_cfg.get('sha256', '?')}")
            log(f"     Flash: {uboot_cfg.get('flash_command', '?')}")
            log("     (reboot after, ~60-90s wait)")
        if nor_fw_cfg:
            log(f"  10. Download NOR firmware from: {nor_fw_cfg.get('url', '?')}")
            log(f"      Expected SHA256: {nor_fw_cfg.get('sha256', '?')}")
            log(f"      Flash: mtd write /tmp/nor-firmware.bin {nor_fw_cfg.get('mtd_partition', '?')}")
        if boot_env_cfg:
            log(f"  13. Set boot_dev={boot_env_cfg.get('boot_dev', '?')} via fw_setenv")

        # In dry-run, download locally and verify hashes
        print()
        log("Downloading files locally to verify hashes...")
        tmp_dir = "/tmp/conwrt-nor-dryrun"
        os.makedirs(tmp_dir, exist_ok=True)

        if not skip_uboot and uboot_cfg:
            uboot_url = uboot_cfg["url"]
            uboot_local = os.path.join(tmp_dir, "uboot-recovery.bin")
            log(f"  Downloading U-Boot to {uboot_local}...")
            try:
                urllib.request.urlretrieve(uboot_url, uboot_local)
                actual_sha256 = sha256_file(uboot_local)
                expected_sha256 = uboot_cfg["sha256"]
                if actual_sha256 == expected_sha256:
                    log("  U-Boot SHA256 verified ✓")
                else:
                    print("  WARNING: U-Boot SHA256 mismatch!", file=sys.stderr)
                    print(f"    Expected: {expected_sha256}", file=sys.stderr)
                    print(f"    Got:      {actual_sha256}", file=sys.stderr)
            except OSError as exc:
                log(f"  Failed to download U-Boot: {exc}")

        if nor_fw_cfg:
            nor_url = nor_fw_cfg["url"]
            nor_local = os.path.join(tmp_dir, "nor-firmware.bin")
            log(f"  Downloading NOR firmware to {nor_local}...")
            try:
                urllib.request.urlretrieve(nor_url, nor_local)
                actual_sha256 = sha256_file(nor_local)
                expected_sha256 = nor_fw_cfg["sha256"]
                if actual_sha256 == expected_sha256:
                    log("  NOR firmware SHA256 verified ✓")
                else:
                    print("  WARNING: NOR firmware SHA256 mismatch!", file=sys.stderr)
                    print(f"    Expected: {expected_sha256}", file=sys.stderr)
                    print(f"    Got:      {actual_sha256}", file=sys.stderr)
            except OSError as exc:
                log(f"  Failed to download NOR firmware: {exc}")

        print()
        log("DRY RUN complete. No changes were made to the router.")
        return 0

    # === LIVE MODE ===
    print()

    def _run_ssh(command: str, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run SSH command on router (delegates to the module-level _ssh_run)."""
        return run_ssh(ip, command, key=ssh_key, timeout=timeout)

    def _install_kmod_mtd_rw() -> bool:
        """Install kmod-mtd-rw with required module parameter. Returns True on success."""
        if not requires_kmod:
            return True
        log("  Installing kmod-mtd-rw...")
        r = _run_ssh("opkg update && opkg install kmod-mtd-rw")
        if r.returncode != 0:
            # Maybe already installed, try to load
            pass
        # Insert module with required param
        if mtd_rw_param:
            insmod_cmd = f"insmod mtd-rw {mtd_rw_param} 2>/dev/null || echo module_load_attempted"
            r = _run_ssh(insmod_cmd)
            if "module_load_attempted" not in r.stdout and r.returncode != 0:
                # Try rmmod then insmod in case it's already loaded without the param
                _run_ssh("rmmod mtd-rw 2>/dev/null")
                r = _run_ssh(f"insmod mtd-rw {mtd_rw_param}")
                if r.returncode != 0:
                    print(f"ERROR: Failed to load mtd-rw module with param '{mtd_rw_param}'.", file=sys.stderr)
                    if r.stderr:
                        print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
                    return False
        log("  kmod-mtd-rw installed and loaded")
        return True

    def _download_and_scp(url: str, local_name: str, remote_path: str,
                          expected_sha256: str) -> bool:
        """Download file locally, verify hash, SCP to router. Returns True on success."""
        local_path = os.path.join("/tmp", local_name)
        log(f"  Downloading {local_name}...")
        try:
            urllib.request.urlretrieve(url, local_path)
        except OSError as exc:
            print(f"ERROR: Failed to download {local_name}: {exc}", file=sys.stderr)
            return False
        actual = sha256_file(local_path)
        if actual != expected_sha256:
            print(f"ERROR: {local_name} SHA256 mismatch!", file=sys.stderr)
            print(f"  Expected: {expected_sha256}", file=sys.stderr)
            print(f"  Got:      {actual}", file=sys.stderr)
            return False
        log(f"  SHA256 verified ✓ ({actual[:16]}...)")
        scp_argv = ["scp", "-O", "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
                     "-i", ssh_key, local_path, f"root@{ip}:{remote_path}"]
        try:
            r = subprocess.run(scp_argv, capture_output=True, text=True, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            print(f"ERROR: SCP of {local_name} timed out.", file=sys.stderr)
            return False
        if r.returncode != 0:
            print(f"ERROR: SCP of {local_name} failed.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            return False
        log(f"  Uploaded to {remote_path}")
        return True

    # Steps 4-8: U-Boot upgrade (unless --skip-uboot)
    if not skip_uboot and uboot_cfg:
        _say("Preparing to flash U-Boot. Do not disconnect power.")
        log("Step 4: Downloading U-Boot binary...")
        if not _download_and_scp(
            uboot_cfg["url"], "uboot-recovery.bin", "/tmp/uboot-recovery.bin",
            uboot_cfg["sha256"],
        ):
            return 1

        # Step 6: Install kmod-mtd-rw
        log("Step 6: Installing kmod-mtd-rw...")
        if not _install_kmod_mtd_rw():
            return 1

        # Step 7: Flash U-Boot
        _say("Flashing U-Boot. This is dangerous. Do not disconnect power.")
        flash_cmd = uboot_cfg.get("flash_command", "mtd -r write /tmp/uboot-recovery.bin /dev/mtd0")
        log(f"Step 7: Flashing U-Boot via: {flash_cmd}")
        print()
        print("  ⚠️  FLASHING U-BOOT — DO NOT DISCONNECT POWER ⚠️")
        print()
        try:
            # mtd -r causes reboot, so the SSH connection will be dropped
            r = subprocess.run(
                ssh_cmd(ip, flash_cmd, key=ssh_key, connect_timeout=10),
                capture_output=True, text=True, timeout=120, check=False,
            )
        except subprocess.TimeoutExpired:
            # Expected: mtd -r reboots the router, SSH drops
            pass
        except OSError as exc:
            # Connection reset is expected during reboot
            if "reset" not in str(exc).lower() and "broken" not in str(exc).lower():
                print(f"WARNING: Unexpected error during U-Boot flash: {exc}", file=sys.stderr)

        # Step 8: Wait for reboot
        _say("Waiting for router to reboot. This takes about 90 seconds.")
        log("Step 8: Waiting for router to reboot (60-90s)...")
        time.sleep(10)  # Brief wait before starting to poll
        reboot_timeout = 120
        reboot_start = time.time()
        if not poll_until(lambda: check_ssh(ip), timeout=reboot_timeout, interval=5):
            print(f"ERROR: Router did not come back after U-Boot flash within {reboot_timeout}s.", file=sys.stderr)
            print("The device may be bricked. Check via serial/UART.", file=sys.stderr)
            return 1
        elapsed = int(time.time() - reboot_start)
        log(f"  Router back online after {elapsed}s")

        # Step 9: Re-install kmod-mtd-rw (lost after reboot)
        log("Step 9: Re-installing kmod-mtd-rw (lost after reboot)...")
        if not _install_kmod_mtd_rw():
            return 1
    else:
        if skip_uboot:
            log("Steps 4-9: Skipped (--skip-uboot)")
        # Still need kmod-mtd-rw for NOR flash
        if requires_kmod:
            log("Installing kmod-mtd-rw...")
            if not _install_kmod_mtd_rw():
                return 1

    # Step 10: Download NOR sysupgrade image
    log("Step 10: Downloading NOR sysupgrade image...")
    if not _download_and_scp(
        nor_fw_cfg["url"], "nor-firmware.bin", "/tmp/nor-firmware.bin",
        nor_fw_cfg["sha256"],
    ):
        return 1

    log("Step 11: Verifying NOR firmware SHA256 on router...")
    r = _run_ssh("sha256sum /tmp/nor-firmware.bin")
    if r.returncode != 0:
        print("ERROR: Failed to compute SHA256 on router.", file=sys.stderr)
        return 1
    actual_hash = r.stdout.strip().split()[0]
    expected_hash = nor_fw_cfg["sha256"]
    if actual_hash != expected_hash:
        print("ERROR: NOR firmware SHA256 hash mismatch!", file=sys.stderr)
        print(f"  Expected: {expected_hash}", file=sys.stderr)
        print(f"  Got:      {actual_hash}", file=sys.stderr)
        return 1
    log("  SHA256 verified ✓")

    # Step 12: Flash NOR firmware (no -r, no reboot)
    _say("Flashing NOR recovery partition.")
    nor_mtd_partition = nor_fw_cfg.get("mtd_partition", "nor_firmware")
    log(f"Step 12: Flashing NOR firmware to '{nor_mtd_partition}' partition...")
    flash_nor_cmd = f"mtd write /tmp/nor-firmware.bin {nor_mtd_partition}"
    r = _run_ssh(flash_nor_cmd, timeout=120)
    if r.returncode != 0:
        print("ERROR: Failed to flash NOR firmware.", file=sys.stderr)
        if r.stderr:
            print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
        return 1
    log("  NOR firmware flashed ✓")

    # Step 12b: Note the recovery hostname for first NOR boot
    recovery_hostname = nor.get("recovery_hostname", "")

    # Step 12c: Fix bootargs for dual-boot compatibility
    bootargs_fix = nor.get("bootargs_fix")
    if bootargs_fix:
        log("Step 12c: Fixing U-Boot bootargs for dual-boot...")
        r = _run_ssh(f"fw_setenv bootargs '{bootargs_fix}'")
        if r.returncode != 0:
            print("ERROR: Failed to set bootargs via fw_setenv.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            return 1
        r = _run_ssh("fw_printenv bootargs")
        log(f"  bootargs: {r.stdout.strip()} ✓")

    # Step 12d: Set boot_local override for NOR boot selection
    boot_local_val = nor.get("boot_local", "")
    if boot_local_val:
        log(f"Step 12d: Setting boot_local={boot_local_val}...")
        r = _run_ssh(f"fw_setenv boot_local {boot_local_val}")
        if r.returncode != 0:
            print("ERROR: Failed to set boot_local via fw_setenv.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            return 1
        r = _run_ssh("fw_printenv boot_local")
        log(f"  {r.stdout.strip()} ✓")

    # Step 13: Set boot_env
    if boot_env_cfg:
        boot_dev_val = boot_env_cfg.get("boot_dev")
        if boot_dev_val:
            log(f"Step 13: Setting boot_dev={boot_dev_val} via fw_setenv...")
            r = _run_ssh(f"fw_setenv boot_dev {boot_dev_val}")
            if r.returncode != 0:
                print("ERROR: Failed to set boot_dev via fw_setenv.", file=sys.stderr)
                if r.stderr:
                    print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
                return 1
            log("  boot_dev set ✓")

            # Step 14: Verify
            log("Step 14: Verifying fw_printenv boot_dev...")
            r = _run_ssh("fw_printenv boot_dev")
            if r.returncode != 0:
                print("WARNING: fw_printenv boot_dev failed.", file=sys.stderr)
                if r.stderr:
                    print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            else:
                output = r.stdout.strip()
                if f"boot_dev={boot_dev_val}" in output:
                    log(f"  Verified: {output} ✓")
                else:
                    print(f"WARNING: boot_dev value unexpected: {output}", file=sys.stderr)
                    print(f"  Expected: boot_dev={boot_dev_val}", file=sys.stderr)
    else:
        log("Steps 13-14: No boot_env config in model JSON, skipping")

    # Step 15: Set bootcount to trigger NOR boot on next power cycle
    boot_method = nor.get("boot_method", {})
    if boot_method.get("recommended") == "bootcount":
        _say("Setting bootcount to trigger NOR boot on next power cycle.")
        log("Step 15: Setting bootcount=3 to trigger NOR boot on next power cycle...")
        r = _run_ssh("fw_setenv bootcount 3")
        if r.returncode != 0:
            print("WARNING: Failed to set bootcount via fw_setenv.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
        else:
            r = _run_ssh("fw_printenv bootcount")
            log(f"  {r.stdout.strip()} ✓")
            log("  On next power cycle: U-Boot will increment bootcount to 4,")
            log("  exceed bootlimit=3, set nand_boot_failed=1, and boot NOR.")
            log("  After NOR boot, reset with: fw_setenv bootcount 0 && reboot")
    else:
        log("Step 15: No bootcount method configured in model JSON, skipping")

    # Step 16: Summary
    print()
    print("=" * 60)
    log("NOR Recovery Setup Complete!")
    print("=" * 60)
    if not skip_uboot and uboot_cfg:
        print(f"  U-Boot:   upgraded to {uboot_cfg.get('version', 'unknown')}")
    else:
        print("  U-Boot:   skipped (--skip-uboot)")
    print(f"  NOR:      flashed {nor_fw_cfg.get('description', 'recovery firmware')}")
    if boot_env_cfg:
        print(f"  boot_dev: {boot_env_cfg.get('boot_dev', 'not set')}")
    if bootargs_fix:
        print("  bootargs: fixed for dual-boot")
    if boot_local_val:
        print(f"  boot_local: {boot_local_val}")
    print()
    print("Verification:")
    post = nor.get("post_setup_verification", {})
    for label, desc in post.items():
        print(f"  {label}: {desc}")
    print()
    print("To switch boot source:")
    print("  NAND (primary):  switch LEFT + fw_setenv bootcount 0 && reboot")
    print("  NOR  (recovery): fw_setenv bootcount 3 && reboot")
    print("                   (switch position does NOT reliably control boot — use bootcount)")
    if recovery_hostname:
        print()
        print("On first NOR boot, set the recovery hostname:")
        print(f"  uci set system.@system[0].hostname='{recovery_hostname}' && uci commit system")
    print()

    _say("NOR recovery setup is complete.")
    return 0
