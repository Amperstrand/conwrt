"""VPN provider use cases — multi-provider WireGuard and OpenVPN setup.

Each provider module registers a use case (vpn-pia, vpn-mullvad, etc.)
via the shared ``register()`` function. The parent ``use_cases`` package
auto-discovers this subpackage through ``pkgutil.iter_modules``; importing
this ``__init__`` triggers registration of all providers.
"""
from . import pia, mullvad, nordvpn, ivpn, surfshark, openvpn as openvpn_uc  # noqa: F401
