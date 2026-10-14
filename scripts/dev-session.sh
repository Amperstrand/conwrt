#!/usr/bin/env bash
# dev-session.sh — per-session worktree + ledger for multi-agent hosts.
#
# Implements the AGENTS.md "Multi-Agent Coordination" rules: one git worktree
# per session (the shared checkout stays a read-only hub), a gitignored
# session ledger (data/active-sessions.jsonl), and a session pid dir so
# teardown kills only what this session started.
#
# Usage:
#   scripts/dev-session.sh start <name> [base-ref]   # default base: origin/master
#   scripts/dev-session.sh stop <name>
#   scripts/dev-session.sh list
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER="$REPO_ROOT/data/active-sessions.jsonl"
pid_dir() { echo "${TMPDIR:-/tmp}/opencode/conwrt-$1/pids"; }

cmd="${1:-}"; shift || true

ledger_add() { # name worktree ports
    mkdir -p "$REPO_ROOT/data"
    printf '{"session":"%s","worktree":"%s","ports":"%s","started":"%s"}\n' \
        "$1" "$2" "${3:-}" "$(date -u +%FT%TZ)" >> "$LEDGER"
    echo "ledger: $LEDGER"
}

case "$cmd" in
  start)
    name="${1:?usage: dev-session.sh start <name> [base-ref]}"
    base="${2:-origin/master}"
    worktree="$REPO_ROOT/../conwrt-$name"
    [ -e "$worktree" ] && { echo "ERROR: $worktree already exists" >&2; exit 1; }
    git -C "$REPO_ROOT" fetch origin master >/dev/null 2>&1 || true
    if git -C "$REPO_ROOT" show-ref --verify --quiet "refs/heads/$name/feat"; then
        echo "resuming existing branch $name/feat"
        git -C "$REPO_ROOT" worktree add "$worktree" "$name/feat"
    else
        git -C "$REPO_ROOT" worktree add "$worktree" -b "$name/feat" "$base"
    fi
    mkdir -p "$(pid_dir "$name")"
    ledger_add "$name" "$worktree" ""
    cat <<EOF
worktree: $worktree  (branch $name/feat from $base)
pid dir:  $(pid_dir "$name")   — write PIDs here; kill ONLY these
next:
  cd $worktree
  python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
EOF
    ;;
  stop)
    name="${1:?usage: dev-session.sh stop <name>}"
    if [ -f "$LEDGER" ]; then
        grep -v "\"session\":\"$name\"" "$LEDGER" > "$LEDGER.tmp" || true
        mv "$LEDGER.tmp" "$LEDGER"
    fi
    pids="$(pid_dir "$name")"
    if compgen -G "$pids/*.pid" >/dev/null; then
        echo "WARNING: leftover pidfiles in $pids — verify and kill before removing:"
        for f in "$pids"/*.pid; do
            pid="$(cat "$f")"
            if [ -d "/proc/$pid" ]; then
                echo "  pid $pid: $(tr '\0' ' ' < "/proc/$pid/cmdline" | cut -c1-100)"
            else
                echo "  pid $pid: dead (stale pidfile)"
            fi
        done
        exit 1
    fi
    git -C "$REPO_ROOT" worktree remove "$REPO_ROOT/../conwrt-$name" 2>/dev/null \
        && echo "worktree removed (branch kept)" \
        || echo "worktree kept (unmerged work or missing)"
    echo "session '$name' stopped"
    ;;
  list)
    [ -f "$LEDGER" ] && cat "$LEDGER" || echo "(no active sessions)"
    ;;
  *)
    sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 1 ;;
esac
