"""Build runtime flash profile from model JSON."""
from __future__ import annotations
from types import SimpleNamespace
from model_loader import load_model


def find_recovery_flash_method(model: dict, method_hint: str = "") -> tuple[str, dict]:
    methods = model.get("flash_methods", {})
    if method_hint and method_hint in methods:
        return method_hint, methods[method_hint]
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

    if is_serial_tftp:
        client_ip = fm.get("tftp_server_ip", "192.168.1.254")
        recovery_ip = fm.get("tftp_router_ip", "192.168.1.1")
    elif is_zycast:
        client_ip = "192.168.1.2"
        recovery_ip = model["openwrt"]["default_ip"]
    elif is_sysupgrade_only:
        client_ip = ""
        recovery_ip = model["openwrt"]["default_ip"]
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
    )
