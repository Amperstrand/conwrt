# Design Note: Unified Flash Architecture — Routers and SBCs

## The Insight

Flashing a Raspberry Pi into a MAAS controller via a companion router is
**the same operation** as flashing a D-Link router into OpenWrt via recovery
mode. The actors, the flow, the safety checks, and the verification are
structurally identical. This means conwrt's flash method system extends
naturally from routers to any device that can:

1. Enter a recovery state (button, missing boot media, EEPROM fallback)
2. Receive firmware over the network (TFTP, HTTP, or both)
3. Write firmware to persistent storage (flash ROM, USB disk, SD card)
4. Boot into a configurable state (uci-defaults, cloud-init, first-boot)

## The Mapping

| conwrt Concept | Router Implementation | Pi Implementation |
|----------------|----------------------|-------------------|
| Recovery mode | Reset button → HTTP/TFTP server | No boot media → EEPROM NET boot |
| Recovery server | Lab OpenWrt router (TFTP) | x1860 bench router (TFTP + HTTP) |
| Firmware | OpenWrt factory/sysupgrade image | Ubuntu Server + cloud-init |
| Flash writer | Recovery HTTP upload | Initramfs dd to USB disk |
| First-boot config | uci-defaults scripts | cloud-init user-data |
| Post-flash verify | SSH + `uci show` | SSH + `maas status` |
| Inventory | MAC + model + flash time | MAC + model + flash time |

## The Device is the Router

The Raspberry Pi is not special. Any SBC with:
- Network boot capability (EEPROM, U-Boot, BIOS PXE)
- Removable/writable persistent storage (USB, SD, eMMC)
- A Linux kernel that supports that storage

...can be treated as a "router" by conwrt's flash method system. The
companion device (x1860, lab router, any OpenWrt box) serves the same role
regardless of what's being flashed: it's the **recovery infrastructure**.

## Rust Trait Design

```rust
/// A method for putting a device into a flashable state and writing
/// firmware to it. Implemented by recovery-http, tftp, netboot-self-flash,
/// serial-flash, zycast, etc.
#[async_trait]
pub trait FlashMethod: Send + Sync {
    /// Human-readable name (e.g., "recovery-http", "netboot-self-flash")
    fn name(&self) -> &str;

    /// What this method requires to work
    fn requirements(&self) -> FlashRequirements;

    /// Check if the device is currently in a flashable state
    async fn detect_recovery(&self, device: &Device) -> Result<bool>;

    /// Prepare the recovery infrastructure (e.g., arm TFTP server)
    async fn prepare(&self, ctx: &FlashContext) -> Result<PreparedFlash>;

    /// Execute the flash (upload firmware, write to storage)
    async fn flash(&self, ctx: &FlashContext, firmware: &FirmwareImage) -> Result<FlashResult>;

    /// Verify the flash succeeded
    async fn verify(&self, device: &Device) -> Result<VerifyResult>;

    /// Expected time in seconds
    fn estimated_time(&self) -> Duration;
}

/// A companion device that provides recovery infrastructure
/// (TFTP server, HTTP server, DHCP with boot options)
#[async_trait]
pub trait RecoveryInfra: Send + Sync {
    /// Deploy boot files (kernel, initramfs, firmware) to this device
    async fn deploy_boot_files(&self, files: &BootFileSet) -> Result<()>;

    /// Configure DHCP + TFTP for the target device's MAC
    async fn arm_recovery(&self, target: &Device) -> Result<()>;

    /// Remove recovery configuration (disarm)
    async fn disarm_recovery(&self) -> Result<()>;

    /// Check recovery server health
    async fn health(&self) -> Result<InfraHealth>;
}

/// A first-boot configuration system
#[async_trait]
pub trait FirstBootConfig: Send + Sync {
    /// Generate the configuration artifact (uci-defaults script, cloud-init YAML, etc.)
    fn generate(&self, params: &ConfigParams) -> Result<String>;

    /// Where to place the configuration (file path, partition, etc.)
    fn target_path(&self) -> &str;

    /// Verify the configuration was applied after boot
    async fn verify_applied(&self, device: &Device) -> Result<bool>;
}
```

## Implementation: `NetbootSelfFlash`

```rust
pub struct NetbootSelfFlash {
    /// The companion router providing TFTP + HTTP
    infra: Arc<dyn RecoveryInfra>,
    /// Boot files to deploy (kernel + initramfs with flash script)
    boot_files: BootFileSet,
    /// Where to download the OS image from
    image_source: ImageSource,
    /// USB disk serial whitelist for safety
    serial_whitelist: Vec<String>,
}

#[async_trait]
impl FlashMethod for NetbootSelfFlash {
    fn name(&self) -> &str { "netboot-self-flash" }

    fn requirements(&self) -> FlashRequirements {
        FlashRequirements {
            companion_device: true,     // needs an OpenWrt router
            target_recovery: "Remove all bootable media from the Pi, power on",
            network: true,
            storage: "USB disk ≥32GB inserted after netboot",
        }
    }

    async fn prepare(&self, ctx: &FlashContext) -> Result<PreparedFlash> {
        // 1. Deploy kernel + initramfs to companion router via TFTP
        self.infra.deploy_boot_files(&self.boot_files).await?;

        // 2. Deploy cloud-init files via HTTP
        self.infra.deploy_boot_files(&ctx.cloud_init_files).await?;

        // 3. Route the SELECTED image: the initramfs fetches exactly
        //    what `conwrt flash --image …` chose — its source URL (or
        //    companion-router path) and its verified SHA-256 are staged
        //    next to the boot files as the flash manifest. The
        //    initramfs must refuse to write any image whose digest does
        //    not match the manifest.
        self.infra
            .deploy_flash_manifest(&FlashManifest {
                image_source: self.image_source.clone(),
                image_sha256: ctx.firmware_sha256,
            })
            .await?;

        // 4. Configure DHCP + TFTP on the companion router
        self.infra.arm_recovery(&ctx.target_device).await?;

        Ok(PreparedFlash {
            instructions: "Remove all bootable media, insert blank USB disk, power on the Pi",
            estimated_time: Duration::from_secs(1800), // ~30 min
        })
    }

    async fn flash(&self, ctx: &FlashContext, firmware: &FirmwareImage) -> Result<FlashResult> {
        // The Pi does everything itself:
        // 1. EEPROM falls through to NET boot
        // 2. TFTP: fetches kernel + initramfs from companion router
        // 3. Initramfs boots, gets network via DHCP
        // 4. Initramfs fetches the OS image FROM THE FLASH MANIFEST (the
        //    source selected on the command line, via companion router
        //    NAT/path), verifies its SHA-256 against the manifest, and
        //    refuses to write on mismatch
        // 5. Initramfs writes the VERIFIED image to USB disk with
        //    serial-whitelist safety
        // 6. Initramfs injects cloud-init from companion router HTTP
        // 7. Write-complete handshake: the initramfs reports the
        //    verified write (digest match, disk synced) BEFORE rebooting
        // 8. Disarm recovery, then reboot:
        //    - success → `disarm_recovery()` tears down DHCP/TFTP/HTTP
        //      and the manifest, so the reboot lands on the new USB
        //      system instead of re-netbooting the self-flash initramfs
        //      (an armed loop would rewrite the disk on every boot);
        //      only THEN is the flash a Success
        //    - error → disarm too: an unauthenticated recovery service
        //      must not stay armed on a failed target

        // Success requires the write-complete handshake, not merely
        // "any system is online". Recovery is disarmed on BOTH paths —
        // success (avoid the rewrite loop) and error (never leave the
        // unauthenticated recovery service armed on a failed target):
        let verified = self.wait_for_verified_write(ctx).await;
        self.infra.disarm_recovery().await?;
        verified?;
        self.wait_for_target_online(ctx).await?;
        Ok(FlashResult::Success)
    }
}
```

## Composability

This design means a single `conwrt flash` command can handle:

```bash
# Flash a router (existing)
conwrt flash --model-id dlink-covr-x1860-a1 --image openwrt.bin

# Flash a Pi into a MAAS controller (new)
conwrt flash --model-id raspberrypi-4b --maas --bench dlink-covr-x1860-a1

# Flash a Pi into a plain Ubuntu server (same method, different cloud-init)
conwrt flash --model-id raspberrypi-4b --ubuntu-server

# Future: flash any SBC with netboot capability
conwrt flash --model-id rock-pi-4 --image whatever.img
```

The flash method, the companion infrastructure, and the first-boot
configuration are all independently swappable. The `--maas` flag selects
a bundle (use case) that wires them together.
