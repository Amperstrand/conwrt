//! AP391x env-block workflow tests: golden stock parse, the field-proven
//! flash recipe applied from the real model registry, and Python-tool byte
//! parity.
//!
//! The fixture (`tests/fixtures/ap391x_cfg1_stock_redacted.bin`) is a
//! sanitized reconstruction of the ap3915i-3893 stock CFG1 captured during
//! the 2026-11-18 zero-serial bring-up (identity values redacted, CRC
//! recomputed by `scripts/uboot_env.py`). The recipe assertions encode the
//! exact change set that was flashed to hardware and cold-boot-verified.

use conwrt_core::uboot_env::UbootEnvBlock;
use std::collections::BTreeMap;
use std::path::Path;

fn fixture() -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ap391x_cfg1_stock_redacted.bin"),
    )
    .expect("fixture present")
}

/// The stock-boot-block CRC offset for AP391x CFG partitions
/// (4-byte CRC + 1-byte active flag).
const CRC_OFFSET: usize = 5;

#[test]
fn golden_stock_block_parses_with_valid_crc() {
    let raw = fixture();
    let env = UbootEnvBlock::from_bytes(&raw, CRC_OFFSET).expect("stock block parses");
    assert!(env.validate_crc(), "stock CRC must validate");
    assert_eq!(env.len(), 63);
    // The three stock traps the recipe exists to fix.
    assert_eq!(env.get("bootcmd"), Some("bootx"));
    assert_eq!(env.get("WATCHDOG_LIMIT"), Some("3"));
    assert!(env.get("bootargs").expect("bootargs").contains("ubi.mtd=0"));
    // `boot_net` (the TFTP rescue command) is stock-provided.
    assert!(
        env.get("boot_net")
            .expect("boot_net")
            .starts_with("tftpboot 0x83600000")
    );
}

#[test]
fn python_tool_byte_parity() {
    // The fixture was written by scripts/uboot_env.py; parsing it in Rust
    // and re-serializing must reproduce the exact same bytes (same var
    // order, same padding, same CRC over the rebuilt payload).
    let raw = fixture();
    let env = UbootEnvBlock::from_bytes(&raw, CRC_OFFSET).expect("parse");
    let out = env.to_bytes();
    assert_eq!(
        out, raw,
        "Rust re-serialization must be byte-identical to the Python tool output"
    );
}

/// Load `final_uboot_vars` from the species model, substituting the
/// `<...>` placeholders with bench-session values the way the bring-up did.
fn final_vars_from_model() -> BTreeMap<String, String> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/extreme-networks-ws-ap3915i.json");
    let model: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("model json"))
            .expect("model parses");
    let vars = model["flash_methods"]["extreme-rdwr-tftp-initramfs"]["final_uboot_vars"]
        .as_object()
        .expect("final_uboot_vars object");
    let mut out = BTreeMap::new();
    for (key, value) in vars {
        let value = value.as_str().expect("string value");
        let value = value
            .replace("<CONWRT_TFTP_SERVER_IP>", "192.168.102.1")
            .replace("<TEMP_AP_IP>", "192.168.102.60");
        out.insert(key.clone(), value);
    }
    out
}

#[test]
fn flash_recipe_application_matches_the_field_verified_change_set() {
    let mut env = UbootEnvBlock::from_bytes(&fixture(), CRC_OFFSET).expect("parse");
    let before: BTreeMap<String, String> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // The recipe, exactly as flashed to ap3915i-3893 (CFG1 v3):
    // final_uboot_vars from the model registry, plus the session-scoped
    // ipaddr and the documented bootargs scrub.
    for (key, value) in final_vars_from_model() {
        env.set(&key, &value);
    }
    env.set("WATCHDOG_COUNT", "0");
    env.set("ipaddr", "192.168.102.60");
    let bootargs = env.get("bootargs").expect("bootargs").to_string();
    let scrubbed: String = bootargs
        .replace("ubi.mtd=0", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    env.set("bootargs", &scrubbed);

    // Serialize + reparse: the flashed block must carry a valid CRC.
    let out = env.to_bytes();
    let flashed = UbootEnvBlock::from_bytes(&out, CRC_OFFSET).expect("reparse");
    assert!(flashed.validate_crc());

    // Exactly the intended keys change — nothing else moves.
    let after: BTreeMap<String, String> = flashed
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut changed_keys: Vec<&str> = before
        .keys()
        .chain(after.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .map(|k| k.as_str())
        .collect();
    changed_keys.sort_unstable();
    // WATCHDOG_COUNT is already "0" on this stock block, so setting it is
    // idempotent insurance rather than a change (the field diff on
    // ap3915i-3893 also showed exactly these seven keys).
    assert_eq!(
        changed_keys,
        vec![
            "MOSTRECENTKERNEL",
            "WATCHDOG_LIMIT",
            "boot_openwrt",
            "bootargs",
            "bootcmd",
            "ipaddr",
            "serverip",
        ]
    );
    assert_eq!(flashed.get("WATCHDOG_COUNT"), Some("0"));

    // The load-address finding: flash boot requires 0x83600000 (the
    // stock boot_net destination), NOT 0x88000000 — proven on hardware
    // 2026-11-18 (see bench docs/BOOT-SAFETY-AP3915I.md).
    assert_eq!(
        flashed.get("bootcmd"),
        Some("run boot_openwrt; run boot_net"),
        "bootcmd must be the semicolon-tail shape"
    );
    assert_eq!(
        flashed.get("boot_openwrt"),
        Some("sf probe; sf read 0x83600000 0x280000 0xc00000; bootm 0x83600000")
    );
    assert!(
        !flashed
            .get("bootargs")
            .expect("bootargs")
            .contains("ubi.mtd=0")
    );
}
