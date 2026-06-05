# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import argparse
import os
import sys
from pathlib import Path

from model_loader import load_model
from flash.context import log
from conwrt.extreme import _ssh_with_password, _scp_with_password, _generate_zyxel_password


def cmd_backup(args: argparse.Namespace) -> int:
    if not args.model_id:
        print("ERROR: --model-id is required.", file=sys.stderr)
        return 1

    model = load_model(args.model_id)
    backup_config = model.get("backup", {})

    if not backup_config.get("method") == "ssh":
        print(f"ERROR: Model '{args.model_id}' does not support SSH backup.", file=sys.stderr)
        return 1

    password = args.password
    serial = args.serial

    if not password and serial:
        password = _generate_zyxel_password(serial)
        if password:
            log(f"Generated stock SSH password from serial {serial}")
        else:
            print("ERROR: --serial provided but zyxel_pwgen not found.", file=sys.stderr)
            print("  Install zyxel_pwgen or use --password to provide the password manually.", file=sys.stderr)
            return 1

    if not password:
        print("ERROR: Provide --serial (for auto password generation) or --password.", file=sys.stderr)
        return 1

    ip = args.ip
    user = args.user

    log(f"Connecting to {user}@{ip} (stock firmware SSH)...")

    list_result = _ssh_with_password(ip, user, password, "cat /proc/mtd", timeout=15)
    if list_result.returncode != 0:
        print(f"ERROR: SSH connection failed: {list_result.stderr.strip()}", file=sys.stderr)
        if "sshpass not found" in list_result.stderr:
            print("  Install sshpass: brew install hudochenkov/sshpass/sshpass", file=sys.stderr)
        return 1

    mtd_output = list_result.stdout.strip()
    if not mtd_output:
        print("ERROR: No MTD partitions found on device.", file=sys.stderr)
        return 1

    mtd_partitions = []
    for line in mtd_output.split("\n"):
        parts = line.split()
        if len(parts) >= 3:
            mtd_name = parts[0]
            mtd_size = parts[1]
            mtd_label = parts[2].strip('"')
            mtd_index = mtd_name.replace("mtd", "").replace(":", "")
            mtd_partitions.append({
                "index": mtd_index,
                "name": mtd_name.rstrip(":"),
                "size": mtd_size,
                "label": mtd_label,
                "device": f"/dev/{mtd_name.rstrip(':')}",
            })

    if args.partitions:
        requested = set(args.partitions.split(","))
        mtd_partitions = [p for p in mtd_partitions if p["index"] in requested]

    critical_names = set(backup_config.get("critical_partitions", []))

    output_dir = args.output_dir
    if not output_dir:
        base_dir = Path(__file__).resolve().parent.parent / "data" / "backups"
        device_id = serial or model.get("id", "unknown")
        output_dir = str(base_dir / device_id)

    os.makedirs(output_dir, exist_ok=True)
    log(f"Backing up {len(mtd_partitions)} MTD partitions to {output_dir}")

    print()
    print(f"{'MTD':<10s} {'Label':<15s} {'Size':<12s} {'Critical':<10s} {'Status'}")
    print("-" * 70)

    failed = []
    for part in mtd_partitions:
        label = part["label"]
        is_critical = label in critical_names
        critical_str = "*** YES ***" if is_critical else ""
        local_path = os.path.join(output_dir, f"mtd{part['index']}_{label}.bin")
        remote_path = f"/tmp/mtd{part['index']}.bin"

        dump_cmd = f"nanddump -f {remote_path} {part['device']}"
        if is_critical:
            log(f"Dumping CRITICAL partition {part['name']} ({label})...")

        dump_result = _ssh_with_password(ip, user, password, dump_cmd, timeout=60)
        if dump_result.returncode != 0:
            print(f"{part['name']:<10s} {label:<15s} {part['size']:<12s} {critical_str:<10s} FAILED (nanddump)")
            if dump_result.stderr:
                log(f"  nanddump error: {dump_result.stderr[:200]}")
            failed.append(part)
            continue

        scp_result = _scp_with_password(ip, user, password, remote_path, local_path, timeout=120)
        if scp_result.returncode != 0:
            print(f"{part['name']:<10s} {label:<15s} {part['size']:<12s} {critical_str:<10s} FAILED (scp)")
            if scp_result.stderr:
                log(f"  scp error: {scp_result.stderr[:200]}")
            failed.append(part)
            continue

        file_size = os.path.getsize(local_path)
        print(f"{part['name']:<10s} {label:<15s} {part['size']:<12s} {critical_str:<10s} OK ({file_size} bytes)")

        _ssh_with_password(ip, user, password, f"rm -f {remote_path}", timeout=10)

    print()
    if failed:
        log(f"WARNING: {len(failed)} partition(s) failed to backup:")
        for p in failed:
            log(f"  mtd{p['index']} ({p['label']})")
    else:
        log(f"All {len(mtd_partitions)} partitions backed up successfully to {output_dir}")

    if critical_names:
        missing_critical = critical_names - {p["label"] for p in mtd_partitions if p not in failed}
        if missing_critical:
            log(f"WARNING: Critical partitions NOT backed up: {missing_critical}")
            log("DO NOT flash this device until these partitions are backed up!")
            return 1

    return 1 if failed else 0
