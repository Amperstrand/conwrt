//! Script linting and line-chunked wire assembly (pure — no I/O).
//!
//! Two jobs, both ported 1:1 from `scripts/serial_transport.py`:
//!
//! 1. [`lint_script`] refuses scripts that cannot survive the serial
//!    channel: lines longer than [`MAX_LINE`] (the tty line buffer) and
//!    runtime variable references inside single quotes (`$N` would arrive
//!    as a literal — generate values on the controlling host instead).
//! 2. The wire-line builders ([`rm_deploy_line`], [`echo_append_line`],
//!    [`sh_runner_line`]) assemble the line-chunked delivery: each script
//!    line is appended to a staging file via `echo '...' >> file`, then the
//!    file runs with `sh` — long scripts never exceed the tty line buffer
//!    because every delivered line is short by construction.

use thiserror::Error;

/// Maximum script line length the tty line buffer survives
/// (`MAX_LINE` in the Python source).
pub const MAX_LINE: usize = 200;

/// Staging path for line-chunked script delivery on the device.
pub const DEPLOY_PATH: &str = "/tmp/conwrt-deploy.sh";

/// A script was refused by the serial-channel linter.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LintError {
    /// The line exceeds [`MAX_LINE`] characters.
    #[error("line {line_no} exceeds {max} chars: {excerpt:?}")]
    LineTooLong {
        /// 1-based line number.
        line_no: usize,
        /// The enforced maximum ([`MAX_LINE`]).
        max: usize,
        /// First 60 characters of the offending line.
        excerpt: String,
    },
    /// A single-quoted payload contains `$` — it will not expand over
    /// serial; generate literals on the controlling host instead.
    #[error(
        "line {line_no}: runtime variable inside single quotes (will not expand over serial): {excerpt:?}"
    )]
    RuntimeVar {
        /// 1-based line number.
        line_no: usize,
        /// First 60 characters of the offending line.
        excerpt: String,
    },
}

/// Python parity: error excerpts carry the first 60 characters of the line.
fn excerpt(line: &str) -> String {
    line.chars().take(60).collect()
}

/// Blank lines and `#` comments are skipped by both the linter and the
/// line-chunked delivery.
pub fn is_skippable_line(line: &str) -> bool {
    let stripped = line.trim();
    stripped.is_empty() || stripped.starts_with('#')
}

/// Lint a script for serial-channel safety (pure).
///
/// Refuses, in Python parity:
///
/// * any line longer than [`MAX_LINE`] characters (checked BEFORE
///   blank/comment skipping — a long comment is still a long line on the
///   wire), and
/// * any `$` inside a single-quoted payload on a non-skippable line.
///
/// `$` outside single quotes (unquoted or double-quoted) is allowed — the
/// rule protects exactly the payloads that cannot expand over serial.
///
/// # Errors
/// [`LintError`] naming the first offending line.
pub fn lint_script(lines: &[impl AsRef<str>]) -> Result<(), LintError> {
    for (idx, line) in lines.iter().enumerate() {
        let line = line.as_ref();
        let line_no = idx + 1;
        if line.chars().count() > MAX_LINE {
            return Err(LintError::LineTooLong {
                line_no,
                max: MAX_LINE,
                excerpt: excerpt(line),
            });
        }
        if is_skippable_line(line) {
            continue;
        }
        for payload in single_quoted_payloads(line) {
            if payload.contains('$') {
                return Err(LintError::RuntimeVar {
                    line_no,
                    excerpt: excerpt(line),
                });
            }
        }
    }
    Ok(())
}

/// Leftmost-first single-quoted payloads, mirroring Python's
/// `re.findall(r"'([^']*)'", line)`: every `'…'` pair yields the bytes
/// between; an unpaired trailing quote yields nothing. Empty payloads
/// (`''`) are yielded (and are harmless — no `$` inside).
fn single_quoted_payloads(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            // Slicing is safe: positions start/stop on ASCII quotes.
            match line[i + 1..].find('\'') {
                Some(rel) => {
                    let start = i + 1;
                    let end = start + rel;
                    out.push(&line[start..end]);
                    i = end + 1;
                }
                None => break, // unpaired quote: no more matches
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Escape a line for a single-quoted shell payload (`'` → `'\''`, the
/// close-quote/escaped-quote/reopen idiom).
pub fn shell_single_quote(line: &str) -> String {
    line.replace('\'', "'\\''")
}

/// Wire line: clear the staging file before the chunked append begins.
pub fn rm_deploy_line() -> String {
    format!("rm -f {DEPLOY_PATH}")
}

/// Wire line: append one script line to the staging file, single-quoted
/// with [`shell_single_quote`] escaping.
pub fn echo_append_line(line: &str) -> String {
    format!("echo '{}' >> {DEPLOY_PATH}", shell_single_quote(line))
}

/// Wire line: run the assembled staging file under `sh`, with the RC
/// marker tail [`crate::collect::rc_command_line`] uses.
pub fn sh_runner_line() -> String {
    format!(
        "sh {DEPLOY_PATH} && echo {} || echo {}",
        crate::collect::RC_OK,
        crate::collect::RC_FAIL
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lint_rejects_runtime_vars_in_single_quotes() {
        // 1:1 with test_serial_transport.py::test_lint_rejects_runtime_vars_in_single_quotes
        assert_eq!(
            lint_script(&["echo '$HOME'"]),
            Err(LintError::RuntimeVar {
                line_no: 1,
                excerpt: "echo '$HOME'".to_string()
            })
        );
    }

    #[test]
    fn lint_rejects_overlong_lines() {
        // 1:1 with test_serial_transport.py::test_lint_rejects_overlong_lines
        let long = "x".repeat(MAX_LINE + 1);
        assert_eq!(
            lint_script(&[long.as_str()]),
            Err(LintError::LineTooLong {
                line_no: 1,
                max: MAX_LINE,
                excerpt: long.chars().take(60).collect()
            })
        );
    }

    #[test]
    fn lint_allows_comments_blank_and_unquoted_vars() {
        assert!(lint_script(&["# a comment", "", "   "]).is_ok());
        assert!(lint_script(&["echo $HOME"]).is_ok()); // unquoted — expands on-device
        assert!(lint_script(&["echo \"a$b\""]).is_ok()); // double quotes are not the trap
        assert!(lint_script(&["true ''"]).is_ok()); // empty payload, no $
    }

    #[test]
    fn lint_reports_first_offending_line_number() {
        assert_eq!(
            lint_script(&["true", "true", "echo '$X'"]),
            Err(LintError::RuntimeVar {
                line_no: 3,
                excerpt: "echo '$X'".to_string()
            })
        );
    }

    #[test]
    fn lint_multiple_quoted_payloads_each_checked() {
        assert_eq!(
            lint_script(&["echo 'ok' 'bad$'"]),
            Err(LintError::RuntimeVar {
                line_no: 1,
                excerpt: "echo 'ok' 'bad$'".to_string()
            })
        );
    }

    #[test]
    fn lint_ignores_dollar_in_unpaired_quote() {
        // `'unpaired $x` — regex findall finds no complete pair → pass
        assert!(lint_script(&["echo 'unpaired $x"]).is_ok());
    }

    #[test]
    fn lint_counts_chars_not_bytes() {
        // 200 chars (multi-byte) passes; 201 single-byte fails
        let ok_line = "é".repeat(MAX_LINE);
        assert!(lint_script(&[ok_line.as_str()]).is_ok());
        let bad_line = "x".repeat(MAX_LINE + 1);
        assert!(lint_script(&[bad_line.as_str()]).is_err());
    }

    #[test]
    fn single_quoted_payloads_matches_python_findall() {
        assert_eq!(single_quoted_payloads("echo '$HOME'"), vec!["$HOME"]);
        assert_eq!(single_quoted_payloads("a 'x' b 'y'"), vec!["x", "y"]);
        // escaped-quote sequence 'it'\''s' → payloads "it" then ""
        assert_eq!(single_quoted_payloads("a 'it'\\''s' b"), vec!["it", ""]);
        assert!(single_quoted_payloads("no quotes").is_empty());
        assert!(single_quoted_payloads("'dangling").is_empty());
    }

    #[test]
    fn shell_escape_matches_python_replace() {
        assert_eq!(shell_single_quote("touch /tmp/x"), "touch /tmp/x");
        assert_eq!(shell_single_quote("it's"), "it'\\''s");
        assert_eq!(shell_single_quote("a'b'c"), "a'\\''b'\\''c");
    }

    #[test]
    fn wire_lines_are_byte_exact() {
        assert_eq!(rm_deploy_line(), "rm -f /tmp/conwrt-deploy.sh");
        assert_eq!(
            echo_append_line("touch /tmp/x"),
            "echo 'touch /tmp/x' >> /tmp/conwrt-deploy.sh"
        );
        assert_eq!(
            echo_append_line("it's"),
            "echo 'it'\\''s' >> /tmp/conwrt-deploy.sh"
        );
        assert_eq!(
            sh_runner_line(),
            "sh /tmp/conwrt-deploy.sh && echo __RC0__ || echo __RC1__"
        );
    }

    #[test]
    fn skippable_lines_match_python_predicates() {
        assert!(is_skippable_line("# comment"));
        assert!(is_skippable_line(""));
        assert!(is_skippable_line("   "));
        assert!(is_skippable_line("  # indented comment"));
        assert!(!is_skippable_line("true"));
        assert!(is_skippable_line("#no-space-after-hash"));
    }
}
