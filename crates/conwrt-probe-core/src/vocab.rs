//! Byte-pattern matching primitives — the no_std stand-in for the
//! Python source's `re` regexes (see the crate-level fidelity table).
//!
//! Every pattern the detection core needs is a literal byte string,
//! optionally followed by one ASCII digit (`U-Boot \d` is the only such
//! shape in the source). ASCII case-insensitive matching covers the
//! `str.lower()` comparisons in `router-probe.py` without allocating a
//! lowercased copy of the (potentially large) HTTP body.

/// A byte pattern: the full expressive power the source-of-truth
/// regexes actually use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    /// Match the literal bytes exactly (case-sensitive).
    Literal(&'static [u8]),
    /// Match the literal bytes immediately followed by one ASCII digit
    /// (the `U-Boot \d` shape).
    LiteralThenDigit(&'static [u8]),
}

impl Pattern {
    /// Find the match position of this pattern in `haystack`, if any.
    #[must_use]
    pub fn find(&self, haystack: &[u8]) -> Option<usize> {
        match *self {
            Pattern::Literal(needle) => find_subslice(haystack, needle),
            Pattern::LiteralThenDigit(prefix) => {
                let mut from = 0;
                while from + prefix.len() < haystack.len() {
                    let at = find_subslice(&haystack[from..], prefix)?;
                    let abs = from + at;
                    let after = abs + prefix.len();
                    if after < haystack.len() && haystack[after].is_ascii_digit() {
                        return Some(abs);
                    }
                    from = abs + 1;
                }
                None
            }
        }
    }

    /// Whether this pattern occurs in `haystack`.
    #[must_use]
    pub fn matches(&self, haystack: &[u8]) -> bool {
        self.find(haystack).is_some()
    }
}

/// Case-sensitive substring search (`"FIRMWARE UPDATE" in body`).
#[must_use]
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find_subslice(haystack, needle).is_some()
}

/// ASCII case-insensitive substring search — the byte twin of Python's
/// `needle in body.lower()`, without allocating the lowered copy.
/// Non-ASCII bytes compare unequal to every ASCII byte, matching
/// Python's ASCII-only `.lower()` behavior for this vocabulary.
#[must_use]
pub fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Plain `memmem`-shaped scan (core-only; the `memchr`/`memmem` crates
/// would be faster but add dependencies to the firmware path for
/// vocabulary-sized needles — not worth it).
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_finds_exact_only() {
        let p = Pattern::Literal(b"root@");
        assert!(p.matches(b"\r\nroot@OpenWrt:~# "));
        assert!(!p.matches(b"ROOT@")); // case-sensitive like the source
        assert_eq!(p.find(b"xx root@yy"), Some(3));
    }

    #[test]
    fn literal_then_digit_requires_digit_after_prefix() {
        let p = Pattern::LiteralThenDigit(b"U-Boot ");
        assert!(p.matches(b"U-Boot 2012.07.22 (Jul 19 2022)"));
        assert!(!p.matches(b"U-Boot bootloader menu")); // no digit
        assert!(!p.matches(b"u-boot 1")); // case-sensitive
        // digit must directly follow the prefix
        assert!(p.matches(b"banner: U-Boot 3"));
    }

    #[test]
    fn literal_then_digit_scans_past_false_prefixes() {
        let p = Pattern::LiteralThenDigit(b"U-Boot ");
        // first occurrence has no digit after it; a later one does
        assert_eq!(p.find(b"U-Boot xx ... U-Boot 2"), Some(14));
    }

    #[test]
    fn literal_then_digit_at_exact_buffer_end_has_no_digit_slot() {
        let p = Pattern::LiteralThenDigit(b"U-Boot ");
        // prefix ending at the last byte cannot be followed by a digit
        assert!(!p.matches(b"... U-Boot "));
    }

    #[test]
    fn contains_is_case_sensitive() {
        assert!(contains(b"FIRMWARE UPDATE PAGE", b"FIRMWARE UPDATE"));
        assert!(!contains(b"firmware update page", b"FIRMWARE UPDATE"));
    }

    #[test]
    fn contains_ci_matches_python_lower_semantics() {
        assert!(contains_ci(b"<html>OpenWrt</html>", b"openwrt"));
        assert!(contains_ci(b"GL-iNet", b"gl-inet"));
        assert!(!contains_ci(b"openwrt", b"openwrtx"));
        assert!(contains_ci(b"anything", b""));
    }

    #[test]
    fn contains_ci_rejects_case_mismatch_in_multibyte_context() {
        // non-ASCII bytes never equal ASCII needle bytes (Python's
        // .lower() leaves them alone too)
        assert!(!contains_ci("úboot".as_bytes(), b"uboot"));
    }

    #[test]
    fn short_haystacks_do_not_panic() {
        assert!(!contains_ci(b"ab", b"abc"));
        assert!(!contains(b"ab", b"abc"));
        assert!(contains(b"ab", b""));
    }
}
