//! Pins the flash-method classification lists (Codex P1 ×2 on #136):
//!
//! - two-stage methods (`extreme-rdwr-tftp-initramfs`, `oem-http`,
//!   `oem-ftp`) must NOT get the recovery/factory image preference —
//!   `SelectedImage.path` is their stage-two sysupgrade artifact, and the
//!   recovery preference made the untyped fallback pick the initramfs
//!   entry for both paths;
//! - `oem-ftp` (Zyxel GS1920) IS two-stage: its handler rejects a missing
//!   initramfs companion before the FTP upload, so it must be in the
//!   initramfs companion set (parity: firmware.py's metadata set).

use conwrt_image::{
    INITRAMFS_FLASH_METHODS, ImageType, RECOVERY_FLASH_METHODS, preferred_image_types,
};

#[test]
fn two_stage_methods_are_not_recovery_preferences() {
    for method in ["extreme-rdwr-tftp-initramfs", "oem-http", "oem-ftp"] {
        assert!(
            !RECOVERY_FLASH_METHODS.contains(&method),
            "{method} must not prefer recovery/factory images (two-stage flow)"
        );
        assert_eq!(
            preferred_image_types(method),
            &[ImageType::Sysupgrade][..],
            "{method} stage two installs the sysupgrade image"
        );
    }
}

#[test]
fn oem_ftp_gets_the_initramfs_companion() {
    assert!(
        INITRAMFS_FLASH_METHODS.contains(&"oem-ftp"),
        "GS1920 oem-ftp is two-stage (handlers_oem requires the initramfs)"
    );
}

#[test]
fn one_stage_recovery_methods_still_prefer_recovery() {
    for method in ["recovery-http", "uboot-tftp", "zycast"] {
        assert!(RECOVERY_FLASH_METHODS.contains(&method));
        assert_eq!(
            preferred_image_types(method),
            &[ImageType::Recovery, ImageType::Factory][..]
        );
    }
}
