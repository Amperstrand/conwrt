//! Pure resolution logic for sourcing **vanilla** OpenWrt images from
//! `downloads.openwrt.org` — parity for `scripts/conwrt/image_source.py`.
//!
//! Everything here is side-effect free (no HTTP, no filesystem, no env
//! reads): environment overrides are values the caller supplies, so the
//! precedence chains are unit-testable in isolation.

use crate::error::ImageError;

/// Fallback release when neither the model nor overrides provide one
/// (`DEFAULT_RELEASE` in image_source.py).
pub const DEFAULT_RELEASE: &str = "24.10.2";

/// Fallback image flavour (`DEFAULT_IMAGE_SUFFIX` in image_source.py).
pub const DEFAULT_IMAGE_SUFFIX: &str = "squashfs-sysupgrade.bin";

/// Default downloads host (`DEFAULT_BASE_URL` in image_source.py).
pub const DEFAULT_DOWNLOADS_BASE: &str = "https://downloads.openwrt.org";

/// The model coordinates needed to source a vanilla image.
///
/// Deliberately decoupled from `conwrt-types`: the typed `OpenwrtInfo`
/// does not carry `release`/`image_suffix` yet (that lands with the
/// models-parity work), so callers fill this from whatever source they
/// have — model JSON, CLI flags, or tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VanillaModel {
    /// Model identifier, used in error messages.
    pub id: String,
    /// OpenWrt target, `<target>/<subtarget>` (e.g. `ramips/mt7621`).
    pub target: String,
    /// ImageBuilder/ASU profile (e.g. `dlink_covr-x1860-a1`).
    pub profile: String,
    /// `openwrt.release` from the model, when present.
    pub release: Option<String>,
    /// `openwrt.image_suffix` from the model, when present.
    pub image_suffix: Option<String>,
}

/// Precedence inputs for release resolution: CLI override > environment
/// > model > [`DEFAULT_RELEASE`] (image_source.py folds `CONWRT_OPENWRT_
/// RELEASE`/`OPENWRT_RELEASE`; the caller reads those and passes them in).
#[derive(Debug, Clone, Default)]
pub struct ReleaseOverrides<'a> {
    /// Explicit `--release` value.
    pub cli: Option<&'a str>,
    /// Value of `CONWRT_OPENWRT_RELEASE` / `OPENWRT_RELEASE`.
    pub env: Option<&'a str>,
}

/// Precedence inputs for suffix resolution: CLI override > environment
/// > model > [`DEFAULT_IMAGE_SUFFIX`] (`CONWRT_IMAGE_SUFFIX`).
#[derive(Debug, Clone, Default)]
pub struct SuffixOverrides<'a> {
    /// Explicit `--image-suffix` value.
    pub cli: Option<&'a str>,
    /// Value of `CONWRT_IMAGE_SUFFIX`.
    pub env: Option<&'a str>,
}

/// `true` for full `X.Y.Z` release versions (the `^\d+\.\d+\.\d+$` check
/// in image_source.py). Majors (`24`) and snapshots are not downloadable
/// from the releases tree.
pub fn is_full_release(candidate: &str) -> bool {
    let mut parts = candidate.split('.');
    let numeric = |part: Option<&str>| {
        part.is_some_and(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    };
    numeric(parts.next())
        && numeric(parts.next())
        && numeric(parts.next())
        && parts.next().is_none()
}

/// Resolves the download release for a model with image_source.py's
/// precedence and validation.
pub fn resolve_release(
    model: &VanillaModel,
    overrides: &ReleaseOverrides<'_>,
) -> Result<String, ImageError> {
    let candidate = overrides
        .cli
        .or(overrides.env)
        .or(model.release.as_deref())
        .unwrap_or(DEFAULT_RELEASE)
        .trim();
    if is_full_release(candidate) {
        Ok(candidate.to_string())
    } else {
        Err(ImageError::InvalidRelease(candidate.to_string()))
    }
}

/// Resolves the image flavour suffix (no validation — any suffix goes,
/// like image_source.py).
pub fn resolve_image_suffix(model: &VanillaModel, overrides: &SuffixOverrides<'_>) -> String {
    overrides
        .cli
        .or(overrides.env)
        .or(model.image_suffix.as_deref())
        .unwrap_or(DEFAULT_IMAGE_SUFFIX)
        .to_string()
}

/// Builds the vanilla image file name:
/// `openwrt-<release>-<target with '/'→'-'>-<profile>-<suffix>`.
///
/// Fails with [`ImageError::InvalidTarget`] when the target lacks the
/// `<target>/<subtarget>` shape, and [`ImageError::MissingProfile`] when
/// the profile is empty — the same `ValueError`s image_filename raises.
pub fn image_filename(
    model: &VanillaModel,
    release: &str,
    suffix: &str,
) -> Result<String, ImageError> {
    if !model.target.contains('/') {
        return Err(ImageError::InvalidTarget {
            model: model.id.clone(),
            target: model.target.clone(),
        });
    }
    if model.profile.is_empty() {
        return Err(ImageError::MissingProfile(model.id.clone()));
    }
    Ok(format!(
        "openwrt-{release}-{}-{}-{suffix}",
        model.target.replace('/', "-"),
        model.profile
    ))
}

/// Target directory URL: `<base>/releases/<release>/targets/<target>`.
pub fn target_dir_url(base: &str, target: &str, release: &str) -> String {
    format!("{base}/releases/{release}/targets/{target}")
}

/// Full image URL: the target directory URL plus the image file name.
pub fn image_url(
    base: &str,
    model: &VanillaModel,
    release: &str,
    suffix: &str,
) -> Result<String, ImageError> {
    Ok(format!(
        "{}/{filename}",
        target_dir_url(base, &model.target, release),
        filename = image_filename(model, release, suffix)?
    ))
}

/// Returns the SHA-256 recorded for `filename` in a `sha256sums` index,
/// lowercased, or `None` when absent.
///
/// OpenWrt's index uses `<hash> *<filename>` (binary-mode marker); plain
/// `<hash>  <filename>` and `#` comment lines are also handled — the
/// exact parsing of `parse_sha256sums` in image_source.py.
pub fn parse_sha256sums(text: &str, filename: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let digest = parts.next()?;
        let listed = parts
            .next()
            .unwrap_or_default()
            .trim_start()
            .trim_start_matches('*')
            .trim();
        if listed == filename {
            return Some(digest.to_lowercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> VanillaModel {
        VanillaModel {
            id: "dlink_covr-x1860-a1".into(),
            target: "ramips/mt7621".into(),
            profile: "dlink_covr-x1860-a1".into(),
            release: Some("25.12.4".into()),
            image_suffix: Some("squashfs-factory.bin".into()),
        }
    }

    #[test]
    fn full_release_validation_matches_the_python_regex() {
        for good in ["24.10.2", "25.12.4", "1.0.0", "99.99.99"] {
            assert!(is_full_release(good), "{good} should be a full release");
        }
        for bad in [
            "24",        // ASU major
            "24.10",     // missing patch
            "24.10.2.1", // four components
            "SNAPSHOT",  // snapshot track
            "24.x.2",    // non-numeric
            ".24.10.2",  // empty component
            "24..2",     // empty component
            "",          // empty
        ] {
            assert!(!is_full_release(bad), "{bad} should be rejected");
        }
    }

    #[test]
    fn release_precedence_is_cli_env_model_default() {
        let model = model();
        let none = ReleaseOverrides::default();
        assert_eq!(resolve_release(&model, &none).expect("model"), "25.12.4");

        let bare = VanillaModel {
            release: None,
            ..model.clone()
        };
        assert_eq!(
            resolve_release(&bare, &none).expect("default"),
            DEFAULT_RELEASE
        );

        let env = ReleaseOverrides {
            cli: None,
            env: Some("24.10.1"),
        };
        assert_eq!(resolve_release(&bare, &env).expect("env"), "24.10.1");
        assert_eq!(
            resolve_release(&model, &env).expect("env beats model"),
            "24.10.1"
        );

        let cli = ReleaseOverrides {
            cli: Some("23.05.5"),
            env: Some("24.10.1"),
        };
        assert_eq!(resolve_release(&model, &cli).expect("cli wins"), "23.05.5");
    }

    #[test]
    fn invalid_release_rejects_majors_like_python() {
        let model = VanillaModel {
            release: Some("24".into()),
            ..model()
        };
        let err = resolve_release(&model, &ReleaseOverrides::default())
            .expect_err("major is not downloadable");
        assert!(matches!(err, ImageError::InvalidRelease(value) if value == "24"));
    }

    #[test]
    fn suffix_precedence_is_cli_env_model_default() {
        let model = model();
        assert_eq!(
            resolve_image_suffix(&model, &SuffixOverrides::default()),
            "squashfs-factory.bin"
        );

        let bare = VanillaModel {
            image_suffix: None,
            ..model.clone()
        };
        assert_eq!(
            resolve_image_suffix(&bare, &SuffixOverrides::default()),
            DEFAULT_IMAGE_SUFFIX
        );

        let env = SuffixOverrides {
            cli: None,
            env: Some("initramfs-kernel.bin"),
        };
        assert_eq!(resolve_image_suffix(&bare, &env), "initramfs-kernel.bin");

        let cli = SuffixOverrides {
            cli: Some("squashfs-sysupgrade.bin"),
            env: Some("initramfs-kernel.bin"),
        };
        assert_eq!(
            resolve_image_suffix(&model, &cli),
            "squashfs-sysupgrade.bin"
        );
    }

    #[test]
    fn filename_format_matches_python() {
        let model = model();
        assert_eq!(
            image_filename(&model, "24.10.2", "squashfs-sysupgrade.bin").expect("filename"),
            "openwrt-24.10.2-ramips-mt7621-dlink_covr-x1860-a1-squashfs-sysupgrade.bin"
        );
    }

    #[test]
    fn filename_rejects_bad_targets_and_missing_profiles() {
        let bad_target = VanillaModel {
            target: "mt7621".into(),
            ..model()
        };
        assert!(matches!(
            image_filename(&bad_target, "24.10.2", DEFAULT_IMAGE_SUFFIX),
            Err(ImageError::InvalidTarget { .. })
        ));

        let no_profile = VanillaModel {
            profile: String::new(),
            ..model()
        };
        assert!(matches!(
            image_filename(&no_profile, "24.10.2", DEFAULT_IMAGE_SUFFIX),
            Err(ImageError::MissingProfile(_))
        ));
    }

    #[test]
    fn url_construction_matches_python() {
        let model = model();
        assert_eq!(
            target_dir_url("https://downloads.openwrt.org", "ramips/mt7621", "24.10.2"),
            "https://downloads.openwrt.org/releases/24.10.2/targets/ramips/mt7621"
        );
        assert_eq!(
            image_url(
                "https://downloads.openwrt.org",
                &model,
                "24.10.2",
                "squashfs-factory.bin"
            )
            .expect("url"),
            "https://downloads.openwrt.org/releases/24.10.2/targets/ramips/mt7621/\
             openwrt-24.10.2-ramips-mt7621-dlink_covr-x1860-a1-squashfs-factory.bin"
        );
    }

    #[test]
    fn sha256sums_parser_handles_openwrt_index_shapes() {
        let index = "\
# comment line
abc123 *openwrt-24.10.2-ramips-mt7621-good.bin
DEF456  openwrt-24.10.2-ramips-mt7621-spaced.bin
   \n
not-a-checksum-line\n
789abc\t*missing-file.bin\n";
        assert_eq!(
            parse_sha256sums(index, "openwrt-24.10.2-ramips-mt7621-good.bin").as_deref(),
            Some("abc123"),
            "binary-mode marker form"
        );
        assert_eq!(
            parse_sha256sums(index, "openwrt-24.10.2-ramips-mt7621-spaced.bin").as_deref(),
            Some("def456"),
            "plain double-space form, digest lowercased"
        );
        assert_eq!(
            parse_sha256sums(index, "openwrt-24.10.2-ramips-mt7621-absent.bin"),
            None,
            "absent file yields None"
        );
    }
}
