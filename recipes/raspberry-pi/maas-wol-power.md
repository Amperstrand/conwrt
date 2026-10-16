# MAAS Wake-on-LAN Power Management

## SECURITY: bench-VLAN-only

The webhook has **no authentication** (the MAAS webhook power driver sends
none). Anyone who can reach the port can send WoL broadcasts. Run it on
the isolated bench VLAN only — never on a shared or production segment
(see the rogue-service rules in AGENTS.md; same discipline as DHCP).

## Overview

MAAS removed the built-in WoL power type in 2.x because it can't power off
or reliably query status. The recommended replacement is the **webhook power
driver** (MAAS 2.9.2+) which delegates power operations to any HTTP endpoint.

This recipe provides a lightweight webhook server that translates MAAS power
commands into WoL magic packets and ping checks.

## Architecture

```
MAAS webhook power driver
    │
    ├── POST /power/on?mac=<MAC>     → sends WoL magic packet
    ├── POST /power/off?mac=<MAC>     → no-op (WoL can't power off)
    └── GET  /power/query?mac=<MAC>&ip=<IP> → ping check
    │
    ▼
maas_wol_webhook.py (on the MAAS controller, port 8081)
    │
    ├── WoL magic packet → UDP broadcast port 9
    └── ping → subprocess
```

## Setup

### 1. Deploy the webhook server (on the MAAS controller)

```bash
# Copy the script
scp scripts/maas_wol_webhook.py ubuntu@<maas-ip>:/tmp/
ssh ubuntu@<maas-ip> 'sudo cp /tmp/maas_wol_webhook.py /usr/local/bin/ && sudo chmod 755 /usr/local/bin/maas_wol_webhook.py'

# Create the systemd service
sudo tee /etc/systemd/system/maas-wol-webhook.service << 'EOF'
[Unit]
Description=MAAS Wake-on-LAN webhook power driver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/maas_wol_webhook.py --port 8081 --interface eth0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now maas-wol-webhook
```

### 2. Enable WoL on the target machine

**In BIOS/UEFI:**
- Enable "Wake on LAN" or "Power On by PCI-E/PCI" (name varies by vendor)
- Some BIOSes need "ErP/EuP" disabled (this cuts power to NIC in S5)

**In the OS (persistent):**
```bash
# Enable WoL on the NIC
sudo ethtool -s eth0 wol g

# Make it persistent (systemd link or netplan)
# Netplan (Ubuntu):
# Add to /etc/netplan/01-netcfg.yaml under the interface:
#   wakeonlan: true
```

**In cloud-init (bake into deployments):**
```yaml
#cloud-config
write_files:
  - path: /etc/systemd/system/enable-wol.service
    content: |
      [Unit]
      Description=Enable Wake-on-LAN
      After=network-online.target
      [Service]
      Type=oneshot
      ExecStart=/usr/sbin/ethtool -s eth0 wol g
      [Install]
      WantedBy=multi-user.target
runcmd:
  - systemctl enable --now enable-wol
```

### 3. Configure MAAS to use the webhook power driver

```bash
maas $PROFILE machine update $SYSTEM_ID \
  power_type=webhook \
  power_parameters_power_on_uri="http://<maas-ip>:8081/power/on?mac=<TARGET_MAC>" \
  power_parameters_power_off_uri="http://<maas-ip>:8081/power/off?mac=<TARGET_MAC>" \
  power_parameters_power_query_uri="http://<maas-ip>:8081/power/query?mac=<TARGET_MAC>&ip=<TARGET_IP>" \
  power_parameters_power_on_regex="status.*:.*running" \
  power_parameters_power_off_regex="status.*:.*stopped"
```

## Limitations

| Operation | Support | Notes |
|-----------|---------|-------|
| Power ON | ✅ | WoL magic packet |
| Power OFF | ⚠️ | No-op — WoL can't power off |
| Power QUERY | ✅ | Ping-based (needs the machine to have an IP) |
| Power CYCLE | ❌ | Not supported (can't power off) |

For full power management (on/off/query/cycle), consider:
- **IPMI/BMC** (server-class hardware)
- **Smart plug** (e.g., TP-Link with webhook server)
- **Redfish** (modern servers)
- **PDU** (power distribution unit)

## Testing

```bash
# Health check
curl http://<maas-ip>:8081/health

# Power query (machine should be pingable)
curl "http://<maas-ip>:8081/power/query?mac=<MAC>&ip=<IP>"

# Power on (send WoL)
curl -X POST "http://<maas-ip>:8081/power/on?mac=<MAC>"

# Via MAAS API
maas $PROFILE machine power-on $SYSTEM_ID
```
