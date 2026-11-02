//! Deterministic per-device fleet identity — the CANONICAL derivations.
//!
//! Two versioned constructions (the version tag is part of the domain):
//!
//! - **v1** (`conwrt-fleet-v1`, FROZEN wire format): first `length` HEX
//!   CHARACTERS of `sha256("<domain-version>:<domain>:<salt>:<mac12>")`.
//!   Byte-compatible with the on-device BusyBox pipeline
//!   (`printf '%s' "…" | sha256sum | cut -c1-N`) in
//!   [`crate::plan::plan_fleet_identity`] and the 1.x Python twin
//!   (`scripts/fleet_secrets.py`). Never change it: devices in the field
//!   derive their root password with it.
//! - **v2** (`conwrt-fleet-v2`, HKDF): first `length` hex characters of
//!   `HKDF-SHA256(ikm = fleet salt, salt = mac12,
//!   info = "conwrt-fleet-v2:<domain>")`. Standard extract-then-expand
//!   (RFC 5869) via the RustCrypto `hkdf` crate — domain separation is a
//!   first-class parameter instead of ad-hoc concatenation discipline.
//!   `length` keeps v1 semantics (hex characters), so the same
//!   validation range (8..=32) applies.
//!
//! `mac12` is the colon-stripped lowercase device MAC (`aabbccddeeff`) —
//! the anchor the operator can read off the unit label before it boots.
//!
//! The on-device SHELL (v1) stays the only thing devices compute
//! themselves; host tooling should use this module (via
//! `conwrt fleet-derive`) for BOTH versions.

use crate::plan::Unsupported;
use alloc::string::{String, ToString};
use core::fmt::Write as _;
use hkdf::Hkdf;
use sha2::Sha256;

/// Version tag of the frozen v1 construction (also embedded in the
/// device-side shell and `/etc/fleet/identity` markers).
pub const DOMAIN_VERSION_V1: &str = "conwrt-fleet-v1";
/// Version tag of the HKDF v2 construction.
pub const DOMAIN_VERSION_V2: &str = "conwrt-fleet-v2";

/// Default derived-password length in hex characters (1.x default).
pub const DEFAULT_PASSWORD_LENGTH: usize = 20;
/// Minimum derived-password length (hex characters).
pub const MIN_PASSWORD_LENGTH: usize = 8;
/// Maximum derived-password length (hex characters).
pub const MAX_PASSWORD_LENGTH: usize = 32;

/// Strip `:` and lowercase a MAC (`AA:BB:…` → `aabb…`).
#[must_use]
pub fn clean_mac(mac: &str) -> String {
    mac.replace(':', "").to_lowercase()
}

/// Is this a syntactically valid fleet salt (8-128 chars of
/// `[A-Za-z0-9_-]` — single-quote shell-safe, as the v1 device shell
/// interpolates it)?
#[must_use]
pub fn salt_is_valid(salt: &str) -> bool {
    (8..=128).contains(&salt.len())
        && salt
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

/// Hex-encode bytes (lowercase) without `format!` churn in a loop.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn check_common(mac12: &str, salt: &str, length: usize) -> Result<(), Unsupported> {
    if !salt_is_valid(salt) {
        return Err(Unsupported::InvalidParams(
            "salt must be 8-128 chars of [A-Za-z0-9_-]".into(),
        ));
    }
    if mac12.len() != 12 || !mac12.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Unsupported::InvalidParams(
            "mac12 must be 12 hex characters (use clean_mac)".into(),
        ));
    }
    if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&length) {
        return Err(Unsupported::InvalidParams(
            "length must be 8..=32 hex characters".into(),
        ));
    }
    Ok(())
}

/// v1 derivation (FROZEN): first `length` hex characters of
/// `sha256("{DOMAIN_VERSION_V1}:{domain}:{salt}:{mac12}")`.
///
/// Byte-compatible with the on-device BusyBox pipeline — the parity
/// goldens in the tests below pin that compatibility.
pub fn derive_v1(
    mac12: &str,
    salt: &str,
    domain: &str,
    length: usize,
) -> Result<String, Unsupported> {
    check_common(mac12, salt, length)?;
    use sha2::Digest;
    let preimage = alloc::format!("{DOMAIN_VERSION_V1}:{domain}:{salt}:{mac12}");
    let digest = Sha256::digest(preimage.as_bytes());
    Ok(hex(&digest[..(length + 1) / 2])[..length].to_string())
}

/// v2 derivation (HKDF, RFC 5869): first `length` hex characters of
/// `HKDF-SHA256(ikm = salt, salt = mac12, info = "{DOMAIN_VERSION_V2}:{domain}")`.
pub fn derive_v2(
    mac12: &str,
    salt: &str,
    domain: &str,
    length: usize,
) -> Result<String, Unsupported> {
    check_common(mac12, salt, length)?;
    let hk = Hkdf::<Sha256>::new(Some(mac12.as_bytes()), salt.as_bytes());
    let info = alloc::format!("{DOMAIN_VERSION_V2}:{domain}");
    // 16 bytes of OKM covers the max 32 hex characters.
    let mut okm = [0u8; 16];
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|_| Unsupported::InvalidParams("hkdf expand failed".into()))?;
    Ok(hex(&okm)[..length].to_string())
}

/// Device hostname: `<prefix>-<mac12>`.
#[must_use]
pub fn hostname(prefix: &str, mac12: &str) -> String {
    alloc::format!("{prefix}-{mac12}")
}

/// Management-AP SSID: `<prefix>_<mac12>`.
#[must_use]
pub fn wifi_ssid(prefix: &str, mac12: &str) -> String {
    alloc::format!("{prefix}_{mac12}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC12: &str = "aabbccddeeff";
    const SALT: &str = "benchsalt0123456789abcdef";

    #[test]
    fn clean_mac_matches_1x() {
        assert_eq!(clean_mac("AA:BB:CC:DD:EE:FF"), MAC12);
        assert_eq!(clean_mac("aa:bb:cc:dd:ee:ff"), MAC12);
    }

    #[test]
    fn salt_validation_matches_1x_charset() {
        assert!(salt_is_valid("12345678"));
        assert!(salt_is_valid("aB-_9012"));
        assert!(!salt_is_valid("short"));
        assert!(!salt_is_valid("has:colon"));
        assert!(!salt_is_valid("has'quote"));
    }

    /// Parity goldens: values computed by the 1.x Python twin
    /// (`fleet_secrets.derive`) and by the on-device BusyBox pipeline.
    /// The wifi domain embeds the network (`wifi:<network>`) — exactly
    /// the preimage the device shell builds.
    #[test]
    fn v1_goldens_match_python_and_device_shell() {
        assert_eq!(
            derive_v1(MAC12, SALT, "root", 20).unwrap(),
            "f19884c76970dfc91875"
        );
        assert_eq!(
            derive_v1(MAC12, SALT, "wifi:fleet", 20).unwrap(),
            "d6356393238d22958aad"
        );
    }

    /// v2 goldens: HKDF-SHA256 per RFC 5869, cross-checked against an
    /// independent Python `cryptography`/hmac implementation. The wifi
    /// domain keeps the `wifi:<network>` shape for structural parity.
    #[test]
    fn v2_goldens_match_independent_hkdf() {
        assert_eq!(
            derive_v2(MAC12, SALT, "root", 20).unwrap(),
            "7e7251ad0df3a558e07c"
        );
        assert_eq!(
            derive_v2(MAC12, SALT, "wifi:fleet", 20).unwrap(),
            "eaf61e9567dd2aaa1af6"
        );
    }

    #[test]
    fn length_semantics_is_hex_characters() {
        // length = N yields N characters, for both versions.
        for n in [8, 16, 20, 32] {
            assert_eq!(derive_v1(MAC12, SALT, "root", n).unwrap().len(), n);
            assert_eq!(derive_v2(MAC12, SALT, "root", n).unwrap().len(), n);
        }
    }

    #[test]
    fn domain_separation_holds() {
        let a = derive_v2(MAC12, SALT, "root", 20).unwrap();
        let b = derive_v2(MAC12, SALT, "wifi", 20).unwrap();
        assert_ne!(a, b);
        // Changing the salt changes both versions (per-device).
        let c = derive_v2(MAC12, "othersalt0123456789ab", "root", 20).unwrap();
        assert_ne!(a, c);
        // Changing the MAC changes the derivation (per-device).
        let d = derive_v2("112233445566", SALT, "root", 20).unwrap();
        assert_ne!(a, d);
    }

    #[test]
    fn invalid_inputs_rejected() {
        assert!(derive_v1("aabbcc", SALT, "root", 20).is_err()); // short mac
        assert!(derive_v1(MAC12, "short", "root", 20).is_err()); // bad salt
        assert!(derive_v1(MAC12, SALT, "root", 4).is_err()); // too short
        assert!(derive_v1(MAC12, SALT, "root", 40).is_err()); // too long
    }

    #[test]
    fn host_helpers() {
        assert_eq!(hostname("nr7101", MAC12), "nr7101-aabbccddeeff");
        assert_eq!(wifi_ssid("nr7101", MAC12), "nr7101_aabbccddeeff");
    }
}
