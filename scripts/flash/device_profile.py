"""Build runtime flash profile from model JSON."""
from __future__ import annotations
from types import SimpleNamespace
from model_loader import load_model


def find_recovery_flash_method(model: dict, method_hint: str = "") -> tuple[str, dict]:
    methods = model.get("flash_methods", {})
    if method_hint and method_hint in methods:
        return method_hint, methods[method_hint]
    # edgeos-kernel-swap and extreme-rdwr-tftp-initramfs are preferred for initial install from stock firmware
    for method_name in ("edgeos-kernel-swap", "extreme-rdwr-tftp-initramfs"):
        if method_name in methods:
            return method_name, methods[method_name]
    for method_name, method_cfg in methods.items():
        if "recovery_ip" in method_cfg:
            return method_name, method_cfg
    for method_name in ("zycast", "dlink-hnap"):
        if method_name in methods:
            return method_name, methods[method_name]
    if "sysupgrade" in methods:
        return "sysupgrade", methods["sysupgrade"]
    available = list(methods.keys())
    serial_methods = [m for m in available if m.startswith("serial-tftp-")]
    if serial_methods and not method_hint:
        raise ValueError(
            f"Model '{model.get('id', '?')}' has no HTTP recovery method. "
            f"Use --serial-method to select a serial flash method. "
            f"Available serial methods: {serial_methods}"
        )
    raise ValueError(
        f"No recovery flash method found in model '{model.get('id', '?')}'. "
        f"Available methods: {available}"
    )


def build_profile_from_model(model_id: str, serial_method: str = "",
                               flash_method: str = "") -> SimpleNamespace:
    """Load a model and build a runtime profile namespace for the recovery script.

    Returns a SimpleNamespace with the same attributes that DeviceProfile used to have,
    so the rest of the state machine code works unchanged.
    """
    model = load_model(model_id)
    if flash_method:
        method_hint = flash_method
    elif serial_method:
        method_hint = f"serial-tftp-{serial_method}"
    else:
        method_hint = ""
    method_name, fm = find_recovery_flash_method(model, method_hint)

    is_serial_tftp = method_name.startswith("serial-tftp")
    is_zycast = method_name == "zycast"
    is_sysupgrade_only = method_name == "sysupgrade" and "recovery_ip" not in fm
    is_mtd_write = method_name == "mtd-write"
    is_edgeos_kernel_swap = method_name == "edgeos-kernel-swap"
    is_extreme_rdwr_tftp = method_name == "extreme-rdwr-tftp-initramfs"

    if is_serial_tftp:
        client_ip = fm.get("tftp_server_ip", "192.168.1.254")
        recovery_ip = fm.get("tftp_router_ip", "192.168.1.1")
    elif is_zycast:
        client_ip = "192.168.1.2"
        recovery_ip = model["openwrt"]["default_ip"]
    elif is_sysupgrade_only or is_mtd_write:
        client_ip = ""
        recovery_ip = model["openwrt"]["default_ip"]
    elif is_edgeos_kernel_swap:
        client_ip = fm.get("openwrt_client_ip", "")
        recovery_ip = fm.get("edgeos_ip", "192.168.1.1")
    elif is_extreme_rdwr_tftp:
        client_ip = fm.get("openwrt_client_ip", "192.168.1.2")
        recovery_ip = fm.get("stock_default_ip", "192.168.1.1")
    else:
        client_ip = fm["client_ip"]
        recovery_ip = fm["recovery_ip"]

    return SimpleNamespace(
        name=model["id"],
        vendor=model["vendor"],
        description=model["description"],
        flash_method=method_name,
        recovery_ip=recovery_ip,
        client_ip=client_ip,
        client_subnet=fm.get("client_subnet", "255.255.255.0"),
        reset_instructions=fm.get("reset_instructions", ""),
        led_pattern=fm.get("led_pattern", ""),
        upload_endpoint=fm.get("upload_endpoint", ""),
        upload_field=fm.get("upload_field", ""),
        trigger_flash_endpoint=fm.get("trigger_flash_endpoint", ""),
        flash_time_seconds=fm.get("flash_time_seconds", 120),
        silence_timeout=fm.get("silence_timeout", 30),
        openwrt_ip=model["openwrt"]["default_ip"],
        openwrt_client_ip=fm.get("openwrt_client_ip", client_ip),
        is_serial_tftp=is_serial_tftp,
        is_zycast=is_zycast,
        is_edgeos_kernel_swap=is_edgeos_kernel_swap,
        is_extreme_rdwr_tftp=is_extreme_rdwr_tftp,
        edgeos_ip=fm.get("edgeos_ip", "192.168.1.1"),
        edgeos_user=fm.get("edgeos_user", "ubnt"),
        edgeos_password=fm.get("edgeos_password", "ubnt"),
        boot_partition=fm.get("boot_partition", "/dev/mmcblk0p1"),
        kernel_path=fm.get("kernel_path", "/vmlinux.64"),
        md5_path=fm.get("md5_path", "/vmlinux.64.md5"),
        port_swap_required=fm.get("port_swap_required", False),
        port_swap_note=fm.get("port_swap_note", ""),
        initramfs_file=fm.get("initramfs_file", ""),
        sysupgrade_file=fm.get("sysupgrade_file", ""),
        serial_baud=fm.get("serial_baud", 115200),
        bootmenu_timeout=fm.get("bootmenu_timeout_seconds", 30),
        bootmenu_interrupt=fm.get("bootmenu_interrupt", "ctrl-c"),
        bootmenu_select_console=fm.get("bootmenu_select_console", "0"),
        tftp_server_ip=fm.get("tftp_server_ip", ""),
        lan_port=fm.get("lan_port", ""),
        uboot_commands=fm.get("uboot_commands", []),
        images=fm.get("images", {}),
        eth_prime=fm.get("eth_prime", ""),
        zycast_multicast_group=fm.get("multicast_group", "225.0.0.0"),
        zycast_multicast_port=fm.get("multicast_port", 5631),
        zycast_image_type=fm.get("image_type", "ras"),
        default_password=fm.get("default_password", ""),
        stock_default_ip=fm.get("stock_default_ip", "192.168.1.1"),
        stock_default_user=fm.get("stock_default_user", "admin"),
        stock_default_password=fm.get("stock_default_password", ""),
        stock_ssh_timeout_disable_commands=fm.get("stock_ssh_timeout_disable_commands", []),
        rdwr_boot_cfg_binary=fm.get("rdwr_boot_cfg_binary", "rdwr_boot_cfg"),
        initramfs_tftp_name=fm.get("initramfs_tftp_name", "vmlinux.gz.uImage.3912"),
        optional_alt_tftp_name=fm.get("optional_alt_tftp_name", ""),
        bootcmd_tftp=fm.get("bootcmd_tftp", "run boot_net"),
        bootcmd_flash=fm.get("bootcmd_flash", "run boot_flash"),
        required_uboot_vars=fm.get("required_uboot_vars", {}),
        final_uboot_vars=fm.get("final_uboot_vars", {}),
        backup_required=fm.get("backup_required", True),
    )
