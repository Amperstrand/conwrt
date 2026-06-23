import argparse

from model_loader import list_models
from conwrt._version import __version__
from flash.context import DEFAULT_IP, SILENCE_TIMEOUT_DEFAULT


def _build_parser() -> argparse.ArgumentParser:
    try:
        available_ids = [m["id"] for m in list_models()]
    except (OSError, ValueError):
        available_ids = []

    parser = argparse.ArgumentParser(
        description="conwrt — flash OpenWrt firmware to routers",
    )
    parser.add_argument("--version", action="version", version=f"conwrt {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    flash_parser = subparsers.add_parser("flash",
        help="Flash firmware to device (default if no subcommand given)")
    flash_parser.add_argument("--model-id", required=False,
                        help=f"Model ID from models/ directory (e.g. glinet-mt3000, dlink-covr-x1860-a1). "
                             f"Auto-detected if device is running OpenWrt. "
                             f"Use 'conwrt list' to see all available. "
                             f"Known: {', '.join(sorted(available_ids)) or 'none loaded'}")

    firmware_group = flash_parser.add_mutually_exclusive_group()
    firmware_group.add_argument("--image", default=None,
                                help="Path to firmware image (vanilla or custom)")
    firmware_group.add_argument("--request-image", action="store_true",
                                help="Request custom image from ASU with baked-in settings")

    flash_parser.add_argument("--ssh-key", default=None,
                        help="Path to SSH public key (default: [ssh].key from config.toml)")
    flash_parser.add_argument("--password", default=None,
                        help="Set root password (default: random, printed once)")
    flash_parser.add_argument("--no-password", action="store_true",
                        help="Skip password (key-only auth)")
    flash_parser.add_argument("--wan-ssh", action="store_true",
                        help="Open SSH on WAN port (requires --ssh-key, disables password auth)")
    flash_parser.add_argument("--interface", default=None,
                        help="Ethernet interface (auto-detected if omitted)")
    flash_parser.add_argument("--no-voice", action="store_true", help="Disable voice guidance")
    flash_parser.add_argument("--no-upload", action="store_true",
                        help="Stop after detecting U-Boot (dry run)")
    flash_parser.add_argument("--yes", action="store_true",
                        help="Skip destructive-operation confirmations")
    flash_parser.add_argument("--no-pcap", action="store_true",
                        help="Disable pcap monitoring (polling-only mode, no scapy needed)")
    flash_parser.add_argument("--force-uboot", action="store_true",
                        help="Force U-Boot recovery mode even if OpenWrt is detected")
    flash_parser.add_argument("--capture", default=None,
                        help="Save pcap capture to file (auto-degrades if no root)")
    flash_parser.add_argument("--router-mac", default="",
                        help="Router's OpenWrt MAC address (for ICMPv6 detection)")
    flash_parser.add_argument("--uboot-mac", default="",
                        help="Router's U-Boot MAC address (for ARP detection)")
    flash_parser.add_argument("--silence-timeout", type=int, default=SILENCE_TIMEOUT_DEFAULT,
                        help="Seconds of no packets before silence event")
    flash_parser.add_argument("--serial-port", default=None,
                        help="Serial port for serial-tftp method (e.g. /dev/cu.usbserial-A50285BI). "
                             "Auto-detected if omitted.")
    flash_parser.add_argument("--flash-method", default=None,
                        help="Flash method to use (e.g. recovery-http, dlink-hnap, sysupgrade, mtd-write, zycast, extreme-rdwr-tftp-initramfs). "
                             "Auto-detected if omitted: sysupgrade if OpenWrt is running, "
                             "otherwise the first recovery method in the model JSON.")
    flash_parser.add_argument("--initramfs", default=None,
                        help="Path to OpenWrt initramfs image (for two-stage flash methods like extreme-rdwr-tftp-initramfs)")
    flash_parser.add_argument("--serial-method", default=None,
                        help="Serial flash method variant (e.g. openwrt-flash, stock-restore). "
                             "Selects the serial-tftp-{method} flash_method from model JSON.")
    flash_parser.add_argument("--serial-baud", type=int, default=115200,
                        help="Serial baud rate (default: 115200)")
    flash_parser.add_argument("--tftp-root", default=None,
                        help="TFTP server root directory. Defaults to image directory.")
    flash_parser.add_argument("--isolate-port", default="",
                        help="Switch port to isolate into VLAN before flashing (e.g. lan5). "
                             "Requires running on OpenWrt with port_isolation in model JSON.")

    subparsers.add_parser("list", help="List available device models")

    uc_parser = subparsers.add_parser("list-use-cases",
        help="List available use case presets")
    uc_parser.add_argument("--model-id", default=None,
        help="Show compatibility for a specific model")

    cache_parser = subparsers.add_parser("cache", help="Manage cached firmware images")
    cache_sub = cache_parser.add_subparsers(dest="cache_command")
    cache_sub.add_parser("list", help="List cached firmware images")
    cache_clean = cache_sub.add_parser("clean", help="Remove cached firmware images")
    cache_clean.add_argument("--model-id", default=None,
                        help="Only clean images for this model")
    cache_clean.add_argument("--keep-latest", action="store_true",
                        help="Keep only the latest build per model")
    cache_clean.add_argument("--yes", action="store_true",
                        help="Skip confirmation prompt")

    mgmt_parser = subparsers.add_parser("setup-mgmt-wifi",
        help="Configure management WiFi on a running router")
    mgmt_parser.add_argument("--ip", default=DEFAULT_IP,
        help="Router IP address")
    mgmt_parser.add_argument("--model-id", default=None,
        help="Model ID (for SSH key detection)")

    backup_parser = subparsers.add_parser("backup",
        help="Backup MTD flash partitions from a stock ZyXEL router via SSH")
    backup_parser.add_argument("--model-id", default="zyxel-nr7101",
        help="Model ID (default: zyxel-nr7101)")
    backup_parser.add_argument("--ip", default=DEFAULT_IP,
        help="Router IP address (default: 192.168.1.1)")
    backup_parser.add_argument("--serial", default=None,
        help="Device serial number (printed on unit label). Used to generate stock SSH password.")
    backup_parser.add_argument("--password", default=None,
        help="Stock SSH password (overrides --serial). Use if zyxel_pwgen is unavailable.")
    backup_parser.add_argument("--output-dir", default=None,
        help="Output directory for partition dumps (default: data/backups/<serial>)")
    backup_parser.add_argument("--partitions", default=None,
        help="Comma-separated list of MTD partitions to dump (e.g. '0,1,2'). Default: all partitions.")
    backup_parser.add_argument("--user", default="root",
        help="SSH username (default: root)")

    fp_parser = subparsers.add_parser("fingerprint",
        help="Fingerprint a device to identify its model")
    fp_parser.add_argument("ip", help="IP address of the device to fingerprint")
    fp_parser.add_argument("--timeout", type=float, default=10.0,
        help="Timeout for probes in seconds (default: 10)")
    fp_parser.add_argument("--json", action="store_true", dest="json_output",
        help="Output results as JSON")

    auto_parser = subparsers.add_parser("auto",
        help="Auto-detect connected router and offer to flash it")
    auto_parser.add_argument("--interface", default=None,
        help="Ethernet interface (auto-detected if omitted)")
    auto_parser.add_argument("--passive-timeout", type=int, default=10,
        help="Seconds to listen for passive detection (default: 10)")
    auto_parser.add_argument("--no-menu", action="store_true",
        help="Print detection results and exit (non-interactive)")

    nor_parser = subparsers.add_parser("setup-nor-recovery",
        help="Set up NOR flash as recovery partition on dual-flash devices (e.g. GL.iNet AR300M)")
    nor_parser.add_argument("--model-id", required=True,
        help="Model ID (e.g. glinet_gl-ar300m-nand)")
    nor_parser.add_argument("--i-want-a-brick", action="store_true",
        help="Safety acknowledgment: required to actually flash (not needed with --dry-run)")
    nor_parser.add_argument("--dry-run", action="store_true",
        help="Download and verify only, do not flash anything")
    nor_parser.add_argument("--skip-uboot", action="store_true",
        help="Skip U-Boot upgrade (only flash NOR firmware and set boot_env)")
    nor_parser.add_argument("--ip", default=None,
        help="Router IP address (default: from model JSON openwrt.default_ip)")
    nor_parser.add_argument("--no-voice", action="store_true",
        help="Disable voice guidance")

    cfg_parser = subparsers.add_parser("configure",
        help="Apply config.toml settings to a running OpenWrt router via SSH")
    cfg_parser.add_argument("--ip", default=DEFAULT_IP,
        help="Router IP address (default: 192.168.1.1)")
    cfg_parser.add_argument("--model-id", default=None,
        help="Model ID for capability filtering (auto-detected if omitted)")
    cfg_parser.add_argument("--interface", default=None,
        help="Ethernet interface (needed for LAN IP change; auto-detected if omitted)")
    cfg_parser.add_argument("--ssh-key", default=None,
        help="Path to SSH public key (default: [ssh].key from config.toml)")
    cfg_parser.add_argument("--password", default=None,
        help="Set root password (default: from config.toml)")
    cfg_parser.add_argument("--no-password", action="store_true",
        help="Skip password, key-only auth")
    cfg_parser.add_argument("--wan-ssh", action="store_true",
        help="Open SSH on WAN port")
    cfg_parser.add_argument("--hostname", default=None,
        help="Set router hostname (overrides config.toml [device].hostname)")
    cfg_parser.add_argument("--wifi-disable", action="store_true",
        help="Disable all WiFi radios")
    cfg_parser.add_argument("--verify", action="store_true",
        help="After applying config, reboot and verify persistence")
    cfg_parser.add_argument("--lan-ip-mode", default=None,
        choices=["static", "mac-hash"],
        help="LAN IP mode: 'static' (use [network] lan_ip) or 'mac-hash' (derive from MAC)")
    cfg_parser.add_argument("--hostname-pattern", default=None,
        choices=["static", "model_mac", "model_seq"],
        help="Hostname pattern: 'static', 'model_mac' (e.g. lyra_aabbcc), 'model_seq'")
    cfg_parser.add_argument("--serial", default=None,
        help="Device serial number (e.g. from sticker) for hostname and inventory")
    cfg_parser.add_argument("--dry-run", action="store_true",
        help="Print commands without executing")
    cfg_parser.add_argument("--transport", default="ssh",
        choices=["ssh", "ubus"],
        help="Transport: 'ssh' (default) or 'ubus' (HTTP JSON-RPC)")
    cfg_parser.add_argument("--ubus-user", default="root",
        help="ubus username (default: root)")
    cfg_parser.add_argument("--ubus-password", default="",
        help="ubus password")

    profile_parser = subparsers.add_parser("profile",
        help="Inspect operator profile (config.toml) plans")
    profile_sub = profile_parser.add_subparsers(dest="profile_command")
    plan_parser = profile_sub.add_parser("plan",
        help="Show what would be applied (ASU + post-install)")
    plan_parser.add_argument("--model-id", default=None,
        help="Model ID for capability filtering")
    profile_parser.set_defaults(profile_command="plan")

    reset_parser = subparsers.add_parser("reset",
        help="Factory reset an OpenWrt router (SSH firstboot or failsafe mode)")
    reset_parser.add_argument("--ip", default=DEFAULT_IP,
        help="Router IP address (default: 192.168.1.1)")
    reset_parser.add_argument("--interface", default=None,
        help="Ethernet interface for failsafe monitoring (auto-detected if omitted)")
    reset_parser.add_argument("--ssh-key", default=None,
        help="Path to SSH private key")
    reset_parser.add_argument("--no-voice", action="store_true",
        help="Disable voice guidance")
    reset_parser.add_argument("--dry-run", action="store_true",
        help="Show what would be done without executing")
    reset_parser.add_argument("--model-id", default=None,
        help="Model ID (for reference/documentation)")

    probe_parser = subparsers.add_parser("probe",
        help="Probe an interface for connected routers")
    probe_parser.add_argument("--interface", default=None,
        help="Ethernet interface (auto-detected if omitted)")
    probe_parser.add_argument("--timeout", type=float, default=3.0,
        help="Per-target timeout in seconds (default: 3)")
    probe_parser.add_argument("--json", action="store_true", dest="json_output",
        help="Output results as JSON")
    probe_parser.add_argument("--quiet", action="store_true",
        help="Only print responding IPs")

    flow_parser = subparsers.add_parser("flow",
        help="Deploy or generate a composite flow (e.g. net4sats)")
    flow_sub = flow_parser.add_subparsers(dest="flow_command")
    flow_sub.add_parser("list", help="List available flows")
    for _verb, _help in (("script", "Print a runnable shell script"),
                         ("instructions", "Print Markdown instructions"),
                         ("run", "Execute the flow against an already-flashed router at --ip")):
        _p = flow_sub.add_parser(_verb, help=_help)
        _p.add_argument("--flow", required=True, help="Flow name (e.g. net4sats)")
        _p.add_argument("--model-id", required=True, help="Model ID (e.g. dlink-covr-x1860-a1)")
        _p.add_argument("--version", default=None, help="OpenWrt version override (default: model's)")
        _p.add_argument("--ip", default=DEFAULT_IP, help="Router IP (for 'run')")
        _p.add_argument("--set", dest="overrides", action="append", default=[],
                        metavar="KEY=VALUE",
                        help="Flow param, repeatable (e.g. --set upstream_ssid=home)")
        _p.add_argument("--set-password", dest="set_password", action="store_true",
                        help="Prepend a step that sets a random root password (composes with any flow)")
        _p.add_argument("--addon", dest="addon", action="append", default=[],
                        metavar="NAME",
                        help="Stack an add-on, repeatable: random-password, set-password, hostname, wan-ssh")
    flow_parser.set_defaults(flow_command="list")

    mig_parser = subparsers.add_parser("lan-migrate",
        help="Re-IP a running router's LAN to the model's lan_subnet (idempotent, self-verifying, auto-rollback)")
    mig_parser.add_argument("--model-id", required=True,
                        help="Model ID whose lan_subnet is the target (e.g. dlink-covr-x1860-a1)")
    mig_parser.add_argument("--ip", default=DEFAULT_IP,
                        help="Router's current LAN IP (default 192.168.1.1)")
    mig_parser.add_argument("--interface", default=None,
                        help="Host ethernet interface (auto-detected if omitted)")
    mig_parser.add_argument("--rollback-secs", type=int, default=60,
                        help="Seconds before the router auto-reverts if the new IP doesn't verify (default 60)")

    return parser
