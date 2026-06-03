"""Shared test helpers for roundtrip comparison of shell scripts vs ops."""


def config_lines(
    script: str,
    *,
    comment_prefix: str = "#",
    keep_echo_with_redirect: bool = False,
    redirect_chars: tuple[str, ...] = (">", ">>"),
) -> list[str]:
    lines = script.strip().splitlines()
    result: list[str] = []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith(comment_prefix):
            continue
        if s.startswith("echo"):
            if keep_echo_with_redirect and any(ch in ln for ch in redirect_chars):
                pass  # echo with redirect — keep
            else:
                continue
        result.append(s)
    return result
