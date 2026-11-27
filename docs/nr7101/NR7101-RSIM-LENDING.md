# NR7101 remote SIM lending — one router's SIM, another router's modem

**Status: PROVEN end-to-end on 2026-11-04.** A port-4 NR7101 borrowed the
silent.link SIM seated in the port-3 NR7101 and carried real internet
traffic over it. The donor radio was parked (lending, not registered) for
the whole borrower session.

This is the supported `wwand-rsim` **provider path** (`wwand:` card
source over SSH + QMI UIM/SIM Access). It replaces the earlier `at:`
source attempt, which cannot initialize a USIM on this firmware.

- Evidence: private bench repo (2026-11-04 session).
- Borrowing unit: NR7101, OpenWrt 25.12.x, `ramips/mt7621`, mipsel_24kc.
- Donor unit: NR7101, OpenWrt 25.12.x.
- Modems: Quectel RG502Q-EA (borrower firmware `RG502QEAAAR11A03M4G`;
  donor `RG502QEAACR13A03M4G_ZYXEL`).
- Driver: Quectel `qmi_wwan_q` (vendor kmod, 6.12.112) on both.
- Manager: wwand `1.8.0_pre48` (hand-deployed) + `datapath_rmnet_nss.uc`
  in `/usr/share/ucode/wwand/` + wwand-rsim plugin/ctl/provider +
  static `rsim-card` (mipsel_24kc).
- SIM: any seated SIM (bench tested with silent.link roaming).

## Topology

```
        Ethernet management (VLAN 1003, SSH transport)
 donor NR7101 (any port)  <------------------------>  borrower NR7101 (any port)
 SIM: silent.link                                     SIM: own dead Telenor (unused)
 wwand + rsim plugin                                  wwand + rsim plugin
   lends card via SIM Access                            rsim_reader =
   radio OFF while lending                              ssh:root@<donor>:wwand:<modem>
        |                                                       |
        +---------------- QMI UIM remote card ------------------+
                                                                |
                                                       QMAP v5 / rmnet_nss
                                                       wwand0 = 10.x/32
                                                       default dev wwand0
```

The donor is managed over Ethernet. Parking its radio for lending does not
touch SSH management. The borrower must never register with its own SIM
while the remote card is active; wwand holds its radio off until the remote
SIM connects.

## The working configuration

### Donor (the router with the card)

Requirements:

1. wwand must own the modem. Delete any legacy `wan` interface that uses
   `/dev/cdc-wdm0` with `proto qmi` — **setting `proto none` is not
   enough**: wwand's device-owner blocklist keys on the interface section
   owning the device and will keep ignoring the modem.
2. The vendor `qmi_wwan_q` driver must win the USB bind race (hotplug
   rebind; see footguns).
3. wwand-rsim provider files:
   - `/usr/share/ucode/wwand/plugins/rsim.uc`
   - `/usr/share/ucode/wwand/ctl/rsim.uc`
   - `/usr/share/ucode/wwand/ctl/rsim_provider.uc`
4. `/usr/bin/rsim-card` (static mipsel build) — the SSH forced-command
   entry point.
5. A restricted SSH key for the borrower:
   `command="rsim-card --serve 'wwand:*'",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding <borrower-key>`
6. Donor radio parked. The plugin does this automatically while lending;
   `wwandctl detach` keeps it off-network when idle.

Donor UCI (the relevant parts; `wan` section deliberately deleted):

```
config wwand_modem 'wwmodem_auto'
    option path 'platform/1e1c0000.xhci/usb2/2-1'
    option mux 'raw_ip'          # lending only; no data interface here

config interface 'lan'
    option device 'br-lan'
    option proto 'static'
    option ipaddr '192.168.5.1'
```

Do **not** create a `config interface` with `proto wwand` on the donor for
this experiment. The donor must not dial its own data session; it only
lends the card.

Observed donor state while lending:

```
MODEM wwmodem_auto (Quectel RG502QEA_ZYXEL_VA, qmi, /dev/cdc-wdm0)
  state       READY
  SIM         imsi -  iccid -
  radio       off — rsim: its card is lent to <borrower>
  SIM sponsor lends its card to <borrower> (SIM Access, radio off) · N commands
  network     Telenor (242/01), roaming  [detached by the operator — wwandctl attach]
```

### Borrower (the router that needs data)

Borrower UCI:

```
config wwand_modem 'wwmodem_auto'
    option path 'platform/1e1c0000.xhci/usb2/2-1'
    option rsim_reader 'ssh:root@<donor>:wwand:wwmodem_auto'

config interface 'wwan0'
    option proto 'wwand'
    option device 'wwand0'
    option modem 'wwmodem_auto'
    option pdp_type 'ipv4'
    option mux_id '1'            # QMAP channel; REQUIRED with rmnet_nss
```

Do **not** set `option mux 'raw_ip'` on the borrower. With the vendor
QMAP driver, raw-IP on the parent is a silent blackhole. Leave `mux`
unset: the `rmnet_nss` add-on is selected by probe, adopts the driver's
QMAP child, and the interface gets `option mux_id '1'`.

Observed borrower state:

```
MODEM wwmodem_auto (Quectel RG502QEA_VA, qmi, /dev/cdc-wdm0)
  state       READY
  SIM         imsi <stale local value>  iccid <remote silent.link ICCID>
  remote SIM  ssh:root@<donor>:wwand:wwmodem_auto · in use by the modem · N commands
  network     Telenor (242/01), roaming, 5G-NSA/LTE (signal-dependent)
  datapath    auto → rmnet_nss · QMAP v5
INTERFACE wwan0 (netdev wwand0)
  state       CONNECTED
```

`wwandctl slots` shows slot 1 present **[active]** with the **remote**
ICCID. `wwandctl datapath` shows:

```
backend      rmnet_nss
parent       wwan0
qmap_version 5
channels     [ { "mux_id": 1, "netdev": "wwand0", "interface": "wwan0" } ]
```

netifd:

```
ifstatus wwan0   -> up: true, proto: wwand, l3_device: wwand0
                    ipv4-address: 10.x.x.x/32
                    route: 0.0.0.0/0
                    dns-server: 8.8.8.8 8.8.4.4
ip route         -> default dev wwand0 scope link
```

Verification that counted:

```
ping -c 3 -W 2 -I wwand0 8.8.8.8        # 0% loss, 58-66 ms
nslookup openwrt.org                    # resolves via 8.8.8.8
uclient-fetch -q -O /tmp/t.html http://example.com   # 577 bytes
```

## Why the AT+CSIM (`at:`) donor path failed

The donor modem's `AT+CSIM` bridge accepted `SELECT` and file-id
`READ BINARY` after a proper EF selection, but refused **SFI-addressed**
`READ BINARY` (`00B0880005`, P1 bit 8 set) with `+CME ERROR: 0`. The
borrower's modem does SFI reads during USIM initialization, retried, then
gave up. This is a firmware/AT bridge limitation, not a card fault.

The provider path avoids it: the donor's wwand reads its own card over
QMI UIM and lends it via SIM Access; the borrower's modem sees a real ATR
and a functional card session.

## Footguns (all hit live)

1. **`wan` proto qmi blocks wwand.** `proto none` leaves the section
   owning `/dev/cdc-wdm0`; wwand still ignores the modem. Delete the
   interface section (after backing up `/etc/config/network`).
2. **Stock `qmi_wwan` wins the USB bind race.** Install a hotplug rebind
   to `qmi_wwan_q` on USB add. On this product the driver creates the
   QMAP child regardless of `qmap_mode=0` (`qmap_mode` is read-only and
   reports 1 after insmod 0). Do not chase raw-IP via the module
   parameter; use the QMAP adopter instead.
3. **`datapath_rmnet_nss.uc` is mandatory and must live in
   `/usr/share/ucode/wwand/`, not `plugins/`.** Without it, `auto` picks
   `raw_ip` on the vendor QMAP parent: link up, address assigned, counters
   move, **zero traffic**.
4. **`option mux_id '1'` is mandatory** with the mux datapath. Without
   it the daemon errors `mux_backend_unavailable` / "configures no mux
   channel" and the modem goes ABSENT.
5. **Changing mux config on a live system leaves netifd holding a stale
   device record.** Recreate the interface (`uci delete` + re-add), or
   reboot. wwand can heal the `DEVICE_CLAIM_FAILED` case, but do not
   stack config changes while the interface is mid-setup.
6. **The add-on probe loses the vendor child name across a wwand daemon
   restart.** The child starts as `wwan0_1` and is renamed to `wwand0`
   by wwand. On a later daemon start the parent is already `wwan0`, the
   `kernel_netdev` hint is the same name, and `wwan0_1` no longer exists
   — the probe declines and the interface stays down behind a healthy
   modem. **Workaround used:** unbind/rebind `2-1:1.4` to `qmi_wwan_q`
   before starting wwand, so the daemon performs a fresh rename and has
   the pre-rename name. **Proposed fix:** probe by the parent/child MAC
   (the add-on already has a `mac()` helper), or accept the stable
   `wwandN` child name.
7. **A modem DMS reset may not re-enumerate USB.** The donor reset once
   for the SIM Access EFS setting and the USB device vanished; a host
   reboot brought it back. Do not power-cycle the donor (PoE) unless the
   console/recovery path is ready; a GPIO 515 modem reset is the board's
   explicit recovery line.
8. **The borrower's IMSI display can be stale.** `wwandctl status` showed
   the borrower's own IMSI with the remote ICCID because the remote
   `6F07` (EF_IMSI) read fails over the UIM remote session (QMI error
   code 48). The ICCID, `wwandctl slots` active ICCID, the donor's
   "lends its card" state, and the APDU command count are the reliable
   identity signals. Registration and authentication used the remote
   card (donor radio off, card sessions active during attach).
9. **Donor root password was empty** with `RootPasswordAuth=on` (only
   global `PasswordAuth=off` blocked it). Set a random root password and
   `RootPasswordAuth=off`; if the lending SSH stream must stay up, do
   **not** restart dropbear — edit the shadow and commit the config for
   next start.

## Rollback

Borrower (RAM-only on this unit): `/etc/init.d/wwand stop` ends the
borrower session; a reboot clears all borrowed-side state. On a
persistent unit: restore `/etc/config/network`, remove `wwand` config,
stop/disable wwand.

Donor: `/etc/init.d/wwand stop` ends lending and restores the donor to
its detached/radio-off state. Restore `/etc/config/network` from the
timestamped backup to re-create the original `wan` qmi section if the
donor is to return to stock duties. Remove `/etc/hotplug.d/usb/20-qmi-wwan-q`,
the provider ctl/plugin files, the restricted key line, and the
`wwmodem_auto` section if full rollback is required. The SIM Access EFS
setting (`sap_security_restrictions=00`) persists in the modem and is
harmless for a standalone donor.

## Unresolved / upstream questions

- **Datapath probe restart bug** (footgun 6): needs a small add-on patch
  and a regression test (daemon restart after the child is renamed). This
  is the highest-value upstream fix; without it, every `wwand` restart
  on a working box can strand the datapath.
- **IMSI over remote UIM**: why does `6F07` read fail (QMI UIM file access
  vs SAP/AT path) while ICCID and authentication work? Status display
  should not lie about the IMSI.
- **SAP vs APDU lending mode**: the donor reports SIM Access; the
  borrower reports `apdu at`. Test whether forcing `donor_mode 'apdu'`
  or `'sap'` changes stability/latency, especially under reconnect.
- **Recovery matrix not yet tested**: interrupted provider SSH, donor
  power loss, borrower restart while lending, missing remote SIM. The
  polite expectation is: borrower radio off on loss, donor radio off on
  return, no duplicate registration, bounded retries.
- **Zero-touch cold boot**: the borrower here is initramfs (all state in
  RAM). The image builder must bake: `qmi_wwan_q.ko` + hotplug rebind,
  wwand + addons + `datapath_rmnet_nss.uc`, wwand-rsim plugin/ctl,
  `rsim-card`, the `rsim_reader`/`mux_id` config, key-only dropbear, and
  the management address (avoid the donor's `.1`). Cold-boot test still
  pending.
- **Pixel 10 Bluetooth SAP / laptop WWAN**: attempted 2026-11-04. The
  Pixel's SAP server works after a programmatic SIM-access grant (the
  Settings authorization prompt is missing on this build); read-only, no
  data session. Laptop WWAN (different IMEI) was not used. See
  `../pixel/PIXEL-10-SAP.md`.

## Tested versions / hashes

- wwand daemon: `1.8.0_pre48` hand-deployed; `datapath_rmnet_nss.uc`
  sha256 `537896483166c9ab7178cb90b42839939a57dff3f57fda21fa2e8c8939ee793b`
- wwand-rsim plugin `rsim.uc`:
  `a4418ddecc5a4de5594b037d9167bad545ec8af68233cd42066037726367cfb0`
- wwand-rsim ctl `ctl/rsim.uc`:
  `f9a5b1ea95372f34fdbbfe27b364a3ebb89c78bf6d3d8a583709d2a1d27b420f`
- wwand-rsim provider `ctl/rsim_provider.uc`:
  `e561781f1d05ed1c0ef5975dfe8f4c21dfccfb198153c3af94b593bc566402f6`
- `rsim-card` (mipsel_24kc static):
  `13c5d521399dc34d0fdab69fd1b5eb75ae2e536a3478b794826a01aab0fa7652`
- `qmi_wwan_q.ko` (6.12.112):
  `156ae23ca655434101acb65e81d4769b6680d0569ba089f95c2d1d916c4141b8`
- OpenWrt 25.12.x, kernel 6.12.x.

All identifiers removed for species-level publication; the private evidence
holds the raw ICCID/IMSI/IMEI/MAC values for bench forensics.
