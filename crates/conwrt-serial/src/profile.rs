//! Device profiles: the generalization layer that makes rescues
//! data-driven instead of gs1900-hardcoded (owner directive
//! 2026-10-25: "refactor and make it modular and parameterizable so
//! similar tooling is easily adapted to other devices").
//!
//! Shape follows OpenOCD's config-fragment doctrine (prior-art report
//! §1.1): composable JSON profiles — `realtek/rtl838x-base` carries
//! family defaults (boot signatures, U-Boot prompt, `rtk network on`,
//! load address), a board profile (`zyxel/gs1900-8hp`) overlays model
//! specifics, and a `find`-style search path lets user directories
//! override shipped ones. Recipes reference placeholders
//! (`{load_addr}`, `{client_ip}`...) resolved from the profile at arm
//! time, so one recipe engine serves every device.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Console-layer facts: how to recognize and interrupt this device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ConsoleSection {
    /// Console baud rate.
    pub baud: u32,
    /// The U-Boot prompt banner (literal match).
    pub uboot_prompt: String,
    /// How to interrupt autoboot: "spaces", "esc", "ctrl_c".
    pub bootdelay_interrupt: String,
    /// Boot-start signatures (any match arms a watcher).
    pub boot_signatures: Vec<String>,
    /// Linux shell prompt marker.
    pub shell_prompt: String,
}

/// U-Boot-layer facts: transfer and boot commands, templated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct UbootSection {
    /// Default RAM load address for tftpboot/loady.
    pub load_addr: String,
    /// Command that brings up U-Boot's network stack.
    pub network_init: String,
    /// Boot command template ({load_addr} substituted).
    pub boot_cmd: String,
    /// Image-verify command template (iminfo ...).
    pub verify_cmd: String,
    /// Dual-partition select command, if the board has one.
    pub partition_select_cmd: Option<String>,
    /// Dual-partition persist command.
    pub partition_save_cmd: Option<String>,
}

/// Flash-layer facts: how images land on this device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct FlashSection {
    /// Supported flashing method: "openwrt-sysupgrade".
    pub method: String,
    /// Flash command template ({image} substituted).
    pub sysupgrade_cmd: String,
}

/// Known behavioral quirks (documented, load-bearing for strategy).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QuirksSection {
    /// busybox lacks stty entirely (serial binary transfers impossible;
    /// both official 24.10.2 and 25.12.6 initramfs — verified 2026-10-25).
    #[serde(default)]
    pub stty_absent: bool,
    /// Console echo of binary is lethal (echo-storm class).
    #[serde(default)]
    pub echo_storm_lethal: bool,
    /// Extra free-form notes.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// A device profile: family defaults + board overlay, fully resolved.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct DeviceProfile {
    pub schema_version: u32,
    /// Profile name, e.g. "zyxel/gs1900-8hp".
    pub profile: String,
    /// Chip/family this board belongs to (informational after resolve).
    pub family: Vec<String>,
    /// Parent profiles merged before this one (chip base first).
    #[serde(default)]
    pub inherits: Vec<String>,
    pub console: ConsoleSection,
    pub uboot: UbootSection,
    pub flash: FlashSection,
    #[serde(default)]
    pub quirks: QuirksSection,
}

impl DeviceProfile {
    /// Load and fully resolve a profile by name against a search path
    /// (first hit wins; user dirs typically precede the shipped set).
    /// `inherits` chains are followed depth-first with cycle rejection;
    /// child fields override parent fields section-by-section where set.
    pub fn load(name: &str, search_path: &[PathBuf]) -> Result<DeviceProfile, String> {
        let mut seen = Vec::new();
        Self::load_inner(name, search_path, &mut seen)
    }

    fn load_inner(
        name: &str,
        search_path: &[PathBuf],
        seen: &mut Vec<String>,
    ) -> Result<DeviceProfile, String> {
        if seen.contains(&name.to_string()) {
            return Err(format!(
                "profile inheritance cycle at {name:?} (chain: {seen:?})"
            ));
        }
        let path = find_profile_file(name, search_path)
            .ok_or_else(|| format!("profile {name:?} not found in search path {search_path:?}"))?;
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let raw: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        seen.push(name.to_string());

        // resolve parents first, then overlay this profile's sections
        let mut merged = DeviceProfile::default();
        let parents = raw
            .get("inherits")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for p in &parents {
            let parent = Self::load_inner(p, search_path, seen)?;
            merged.merge_from(&parent);
        }
        let mut own: DeviceProfile =
            serde_json::from_value(raw).map_err(|e| format!("profile {name:?}: {e}"))?;
        own.merge_onto(&mut merged);
        merged.schema_version = own.schema_version;
        merged.profile = own.profile;
        merged.family = own.family;
        merged.inherits = own.inherits;
        Ok(merged)
    }

    /// Overlay `other`'s set fields onto self (child wins where set;
    /// for simplicity, sections replace wholesale when the child
    /// declares them — profiles are small and explicit beats clever).
    fn merge_onto(&self, base: &mut DeviceProfile) {
        if self.console != ConsoleSection::default() {
            base.console = self.console.clone();
        }
        if self.uboot != UbootSection::default() {
            base.uboot = self.uboot.clone();
        }
        if self.flash != FlashSection::default() {
            base.flash = self.flash.clone();
        }
        // quirks merge FIELD-WISE (a board declaring only notes must not
        // erase the family's stty_absent): booleans OR, notes append+dedup
        base.quirks.stty_absent |= self.quirks.stty_absent;
        base.quirks.echo_storm_lethal |= self.quirks.echo_storm_lethal;
        for n in &self.quirks.notes {
            if !base.quirks.notes.contains(n) {
                base.quirks.notes.push(n.clone());
            }
        }
    }

    fn merge_from(&mut self, other: &DeviceProfile) {
        if self.console == ConsoleSection::default() {
            self.console = other.console.clone();
        }
        if self.uboot == UbootSection::default() {
            self.uboot = other.uboot.clone();
        }
        if self.flash == FlashSection::default() {
            self.flash = other.flash.clone();
        }
        if self.quirks == QuirksSection::default() {
            self.quirks = other.quirks.clone();
        } else {
            // field-wise for quirks (see merge_onto)
            self.quirks.stty_absent |= other.quirks.stty_absent;
            self.quirks.echo_storm_lethal |= other.quirks.echo_storm_lethal;
            for n in &other.quirks.notes {
                if !self.quirks.notes.contains(n) {
                    self.quirks.notes.push(n.clone());
                }
            }
        }
    }

    /// Substitute profile placeholders in a command template:
    /// {load_addr}, {image}, {client_ip}, {server_ip}.
    pub fn render(&self, template: &str, image: &str, client_ip: &str, server_ip: &str) -> String {
        template
            .replace("{load_addr}", &self.uboot.load_addr)
            .replace("{image}", image)
            .replace("{client_ip}", client_ip)
            .replace("{server_ip}", server_ip)
    }
}

fn find_profile_file(name: &str, search_path: &[PathBuf]) -> Option<PathBuf> {
    let rel = format!("devices/{name}.json");
    for dir in search_path {
        let p = dir.join(&rel);
        if p.exists() {
            return Some(p);
        }
    }
    // also allow absolute paths and cwd-relative for convenience
    let direct = Path::new(name);
    if direct.exists() {
        return Some(direct.to_path_buf());
    }
    None
}

/// List every profile available on a search path (name = relative path
/// under devices/, extension stripped) — for `conwrt devices` listings.
pub fn list_profiles(search_path: &[PathBuf]) -> BTreeMap<String, PathBuf> {
    let mut out = BTreeMap::new();
    for dir in search_path {
        let root = dir.join("devices");
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    out.insert(stem.to_string(), p);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profiles")
    }

    #[test]
    fn resolves_inheritance_with_child_override() {
        let dir = fixture_dir();
        let p = DeviceProfile::load("zyxel/gs1900-8hp", &[dir.clone()]).expect("load");
        // family default from rtl838x-base
        assert_eq!(p.console.uboot_prompt, "RTL838x#");
        assert_eq!(p.uboot.network_init, "rtk network on");
        // board override
        assert_eq!(p.console.baud, 115200);
        // quirk merged from base
        assert!(p.quirks.stty_absent);
    }

    #[test]
    fn second_device_proves_generality() {
        let dir = fixture_dir();
        let p = DeviceProfile::load("dlink/dgs-1210-16", &[dir]).expect("load");
        // different interrupt method, different prompt, same family base
        assert_eq!(p.console.bootdelay_interrupt, "esc_then_ctrl_c");
        assert_eq!(p.console.uboot_prompt, "u-boot>#");
        assert!(
            p.console
                .boot_signatures
                .contains(&"Hit Esc key to stop autoboot".to_string())
        );
        assert_eq!(p.uboot.load_addr, "0x8f000000");
    }

    #[test]
    fn rejects_cycles_and_missing() {
        let dir = fixture_dir();
        assert!(DeviceProfile::load("no/such-profile", &[dir.clone()]).is_err());
        assert!(DeviceProfile::load("cycle/a", &[dir]).is_err());
    }

    #[test]
    fn renders_templates() {
        let dir = fixture_dir();
        let p = DeviceProfile::load("zyxel/gs1900-8hp", &[dir]).unwrap();
        assert_eq!(
            p.render(
                "bootm {load_addr} from {server_ip}",
                "img",
                "192.168.1.1",
                "192.168.1.10"
            ),
            "bootm 0x84f00000 from 192.168.1.10"
        );
    }
}
