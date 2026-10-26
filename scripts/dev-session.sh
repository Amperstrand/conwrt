#!/usr/bin/env bash
# dev-session.sh — per-session worktree + ledger for multi-agent hosts.
#
# Implements the AGENTS.md "Multi-Agent Coordination" rules: one git worktree
# per session (the shared checkout stays a read-only hub), a gitignored
# session ledger (data/active-sessions.jsonl), and a session pid dir so
# teardown kills only what this session started.
#
# Usage:
#   scripts/dev-session.sh start <name> [base-ref]   # default base: origin/master;
#                                                     # writes worktree-local
#                                                     # .cargo/config.toml
#   scripts/dev-session.sh stop <name>                # reap target/, remove worktree,
#                                                     # drop merged branch, prune,
#                                                     # delete merged [gone]-remote
#                                                     # branches
#   scripts/dev-session.sh list
#   scripts/dev-session.sh sweep [--apply] [--days N] [name ...]
#                                                     # classify every worktree:
#                                                     # retire merged, reap idle
#                                                     # target/ dirs (default N=4
#                                                     # days without PR activity),
#                                                     # protect dirty/unpushed.
#                                                     # Dry-run unless --apply.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The ORIGINAL tree the script was invoked from: the sweep's
# protect-yourself guard compares against THIS, never the hub (review
# round 1 on #579 — a worktree sweep must not be able to retire itself).
INVOKE_ROOT="$REPO_ROOT"
# #480: the ledger and the worktree sweep are MAIN-checkout (hub) state.
# Invoked from a feature worktree, the script-dir fallback would target
# the worktree's own data/ ledger — resolve the hub (git lists the main
# working tree first) and prefer it.
if _hub="$(git -C "$REPO_ROOT" worktree list --porcelain 2>/dev/null \
        | awk '$1=="worktree"{print substr($0,10); exit}')" \
   && [ -n "$_hub" ] && [ -d "$_hub" ]; then
    REPO_ROOT="$_hub"
fi
LEDGER="$REPO_ROOT/data/active-sessions.jsonl"
pid_dir() { echo "${TMPDIR:-/tmp}/opencode/conwrt-$1/pids"; }

cmd="${1:-}"; shift || true

ledger_lock() { echo "$REPO_ROOT/data/.sessions.lock"; }

# All ledger rewrites run under an flock so a concurrent `start` append
# can never be lost to a filter-rewrite (lost-update race, review finding).
ledger_add() { # name worktree ports
    mkdir -p "$REPO_ROOT/data"
    (
      flock 9
      printf '{"session":"%s","worktree":"%s","ports":"%s","started":"%s"}\n' \
          "$1" "$2" "${3:-}" "$(date -u +%FT%TZ)" >> "$LEDGER"
    ) 9>"$(ledger_lock)"
    echo "ledger: $LEDGER"
}

ledger_drop() { # -F pattern (exact fixed string, e.g. '"worktree":"/p/conwrt-esp32",')
    [ -f "$LEDGER" ] || return 0
    (
      flock 9
      grep -v -F "$1" "$LEDGER" > "$LEDGER.tmp" || true
      mv "$LEDGER.tmp" "$LEDGER"
    ) 9>"$(ledger_lock)"
}

ledger_drop_worktree() {
    # Drop the canonical form and the pre-#213 legacy form
    # ($REPO_ROOT/../conwrt-<name>) recorded by older `start` runs.
    ledger_drop "\"worktree\":\"$1\","
    ledger_drop "\"worktree\":\"$REPO_ROOT/../$(basename "$1")\","
}

# Structural target isolation (AGENTS.md multi-agent rules): a host-global
# ~/.cargo/config.toml may pin one shared target-dir for every checkout on
# the machine — concurrent lanes would then interleave artifacts in one
# cache. This per-worktree config wins (nearest .cargo dir takes
# precedence), so each lane builds into <worktree>/target and `stop`/`sweep`
# reclaim it with the lane. Git-invisible via the bare `config.toml`
# ignore pattern in .gitignore.
ensure_cargo_isolation() { # worktree
    local cfg="$1/.cargo/config.toml"
    if [ -e "$cfg" ]; then
        [ -f "$cfg" ] \
            || echo "WARNING: $cfg exists and is not a regular file" >&2
        return 0
    fi
    mkdir -p "$1/.cargo"
    cat > "$cfg" <<'TOML'
# Written by scripts/dev-session.sh start. Overrides any host-global
# ~/.cargo/config.toml target-dir pin: this lane's build artifacts stay
# inside the worktree and are reclaimed with it.
[build]
target-dir = "target"
TOML
    echo "cargo target isolation: $cfg"
}

case "$cmd" in
  start)
    name="${1:?usage: dev-session.sh start <name> [base-ref]}"
    base="${2:-origin/master}"
    worktree="$(dirname "$REPO_ROOT")/conwrt-$name"
    [ -e "$worktree" ] && { echo "ERROR: $worktree already exists" >&2; exit 1; }
    git -C "$REPO_ROOT" fetch origin master >/dev/null 2>&1 || true
    if git -C "$REPO_ROOT" show-ref --verify --quiet "refs/heads/$name/feat"; then
        echo "resuming existing branch $name/feat"
        git -C "$REPO_ROOT" worktree add "$worktree" "$name/feat"
    else
        git -C "$REPO_ROOT" worktree add "$worktree" -b "$name/feat" "$base"
    fi
    ensure_cargo_isolation "$worktree"
    mkdir -p "$(pid_dir "$name")"
    ledger_add "$name" "$worktree" ""
    cat <<EOF
worktree: $worktree  (branch $name/feat from $base)
cargo:    worktree-local target/ (isolated from any host-global pin)
pid dir:  $(pid_dir "$name")   — write PIDs here; kill ONLY these
next:
  cd $worktree
  python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
EOF
    ;;
  stop)
    name="${1:?usage: dev-session.sh stop <name>}"
    worktree="$(dirname "$REPO_ROOT")/conwrt-$name"
    branch="$(git -C "$REPO_ROOT" worktree list --porcelain \
        | awk -v wt="$worktree" '$1=="worktree"{p=substr($0,10)} $1=="branch" && p==wt{print substr($2,12); exit}')"
    ledger_drop "\"session\":\"$name\","
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
    git -C "$REPO_ROOT" fetch --prune origin >/dev/null 2>&1 \
        || echo "WARNING: fetch failed — merge checks use the last-known origin/master"
    registered=no
    git -C "$REPO_ROOT" worktree list --porcelain \
        | awk -v w="$worktree" '$1=="worktree" && substr($0,10)==w{found=1} END{exit !found}' \
        && registered=yes
    if [ "$registered" = yes ]; then
        rm -rf "$worktree/target" 2>/dev/null || true
    fi
    git -C "$REPO_ROOT" worktree remove "$worktree" 2>/dev/null \
        && echo "worktree removed" \
        || echo "worktree kept (unmerged work or missing)"
    if [ -n "$branch" ] \
        && git -C "$REPO_ROOT" merge-base --is-ancestor "$branch" origin/master 2>/dev/null; then
        git -C "$REPO_ROOT" branch -d "$branch" 2>/dev/null \
            && echo "branch $branch deleted (merged into origin/master)" \
            || echo "branch $branch kept (delete manually if done)"
    elif [ -n "$branch" ]; then
        echo "branch $branch kept (not merged into origin/master)"
    fi
    git -C "$REPO_ROOT" worktree prune
    # An unmerged branch whose remote is gone may hold someone's unpushed
    # work — report it, never destroy it. Only merged-gone branches are
    # safe to batch-delete.
    git -C "$REPO_ROOT" for-each-ref \
        --format='%(refname:short) %(upstream:track)' refs/heads \
        | awk '$2 == "[gone]" {print $1}' \
        | while IFS= read -r br; do
            if git -C "$REPO_ROOT" merge-base --is-ancestor "$br" origin/master 2>/dev/null; then
                git -C "$REPO_ROOT" branch -d "$br" >/dev/null 2>&1 \
                    && echo "branch $br deleted (merged, remote gone)" \
                    || echo "branch $br kept (delete refused — checked out here? remove manually)"
            else
                echo "branch $br kept (remote gone, not merged into origin/master)"
            fi
          done
    echo "session '$name' stopped"
    ;;
  list)
    [ -f "$LEDGER" ] && cat "$LEDGER" || echo "(no active sessions)"
    ;;
  sweep)
    # Worktree reaper (AGENTS.md "Worktree lifecycle and disk reaping"):
    # retire merged lanes, reclaim target/ from idle ones, never touch
    # dirty or unpushed work. Dry-run by default; --apply acts.
    apply=0; idle_days=4; pressure=0; filter=()
    while [ $# -gt 0 ]; do
      case "$1" in
        --apply) apply=1 ;;
        --days) idle_days="${2:?--days needs a number}"; shift ;;
        --pressure) apply=1; idle_days=0; pressure=1 ;;
        -*) echo "unknown option: $1" >&2; exit 1 ;;
        *) filter+=("$1") ;;
      esac
      shift
    done
    now=$(date +%s)
    git -C "$REPO_ROOT" fetch origin master >/dev/null 2>&1 \
        || echo "WARNING: fetch failed — MERGED classification uses the last-known origin/master"
    hub="$(git -C "$REPO_ROOT" worktree list --porcelain \
        | awk '$1=="worktree"{print substr($0,10); exit}')"
    current="$(git -C "$INVOKE_ROOT" rev-parse --show-toplevel 2>/dev/null || true)"
    # One lookup for all open PRs: "branch|updatedAt|number". gh failure
    # degrades to "unknown PR state" — sweep then never reaps.
    pr_map="$(gh pr list -R Amperstrand/conwrt --state open \
        --json headRefName,updatedAt,number --limit 200 2>/dev/null \
        | python3 -c '
import json, sys
for pr in json.load(sys.stdin):
    print(pr["headRefName"] + "|" + pr["updatedAt"] + "|" + str(pr["number"]))
' || true)"
    remote_branches="$(git -C "$REPO_ROOT" for-each-ref \
        --format='%(refname:short)' refs/remotes/origin)"

    matches_filter() { # name (conwrt-<session> or <session>)
      [ ${#filter[@]} -eq 0 ] && return 0
      local n; for n in "${filter[@]}"; do
        [ "$n" = "$1" ] || [ "conwrt-$n" = "$1" ] && return 0
      done; return 1
    }

    printf '%-22s %-38s %-16s %10s  %s\n' \
        WORKTREE BRANCH STATE TARGET-MB ACTION
    git -C "$REPO_ROOT" worktree list --porcelain \
      | awk '$1=="worktree"{print substr($0,10)}' \
      | while IFS= read -r wt; do
        name="$(basename "$wt")"
        matches_filter "$name" || continue
        branch="$(git -C "$REPO_ROOT" worktree list --porcelain \
            | awk -v w="$wt" '$1=="worktree"{p=substr($0,10)} $1=="branch" && p==w{print substr($2,12); exit}')"
        mb=0
        [ -d "$wt" ] && mb=$(du -sm "$wt/target" 2>/dev/null | cut -f1 || echo 0)
        if [ ! -d "$wt" ]; then
            state=PRUNABLE; action="prune registration"
            [ "$apply" = 1 ] && git -C "$REPO_ROOT" worktree prune
        elif [ -z "$branch" ]; then
            state=DETACHED; action="report only"
        elif [ "$wt" = "$hub" ]; then
            state=HUB; action="report only"
        elif ! status_out="$(git -C "$wt" status --porcelain 2>/dev/null)"; then
            state=UNKNOWN; action="PROTECTED (git status failed)"
        elif [ -n "$status_out" ]; then
            state=DIRTY; action="PROTECTED (uncommitted work)"
        elif [ "$branch" = "master" ] || [ "$(git -C "$REPO_ROOT" rev-parse "$branch" 2>/dev/null)" = "$(git -C "$REPO_ROOT" rev-parse origin/master 2>/dev/null)" ]; then
            state=NO-COMMITS; action="PROTECTED (fresh lane, no unique commits)"
        elif git -C "$REPO_ROOT" merge-base --is-ancestor "$branch" origin/master 2>/dev/null; then
            state=MERGED
            # The local tip may be merged while the remote branch moved on
            # with unmerged work: verify the remote head too.
            remote_merged=yes
            if printf '%s\n' "$remote_branches" | grep -qxF "origin/$branch"; then
                git -C "$REPO_ROOT" fetch origin "$branch" >/dev/null 2>&1 || true
                git -C "$REPO_ROOT" merge-base --is-ancestor "origin/$branch" origin/master 2>/dev/null \
                    || remote_merged=no
            fi
            if [ "$remote_merged" = no ]; then
                action="report only (remote branch ahead of merged local tip)"
            elif compgen -G "$(pid_dir "${name#conwrt-}")/*.pid" >/dev/null; then
                action="PROTECTED (leftover pidfiles — run stop)"
            else
                action="retire (remove worktree + branch)"
                retired=0
                if [ "$apply" = 1 ] && [ "$wt" != "$current" ]; then
                    rm -rf "$wt/target" 2>/dev/null || true
                    git -C "$wt" clean -qfdx 2>/dev/null || true
                    # No --force: git re-checks cleanliness atomically at
                    # removal time, so files created after our status check
                    # abort the retirement instead of being deleted.
                    if git -C "$REPO_ROOT" worktree remove "$wt" 2>/dev/null \
                        && git -C "$REPO_ROOT" branch -d "$branch" 2>/dev/null; then
                        action="RETIRED"; retired=1
                    else
                        action="retire FAILED (manual review)"
                    fi
                elif [ "$apply" = 1 ]; then
                    action="skip (current worktree)"
                fi
                if [ "$retired" = 1 ]; then
                    ledger_drop_worktree "$wt"
                fi
            fi
        elif ! printf '%s\n' "$remote_branches" | grep -qxF "origin/$branch"; then
            state=UNPUSHED; action="PROTECTED (branch not on remote)"
        else
            pr_line="$(printf '%s\n' "$pr_map" | awk -F'|' -v b="$branch" '$1==b{print; exit}')"
            if [ -z "$pr_line" ] && [ -z "$pr_map" ]; then
                state=UNKNOWN; action="report only (gh unavailable)"
            elif [ -z "$pr_line" ]; then
                state=NO-OPEN-PR; action="report only"
            else
                updated="$(printf '%s' "$pr_line" | cut -d'|' -f2)"
                age=$(( (now - $(date -d "$updated" +%s)) / 86400 ))
                if [ "$age" -ge "$idle_days" ]; then
                    state="IDLE-${age}d"
                    action="reap target/ (PR idle >= ${idle_days}d)"
                    if [ "$apply" = 1 ] && [ "$wt" = "$current" ]; then
                        action="skip (current worktree)"
                    elif [ "$apply" = 1 ]; then
                        rm -rf "$wt/target" 2>/dev/null || true
                        action="REAPED target/"
                    fi
                else
                    state="ACTIVE-${age}d"
                    action="leave alone"
                fi
            fi
        fi
        printf '%-22s %-38s %-16s %10s  %s\n' \
            "$name" "${branch:-—}" "$state" "$mb" "$action"
      done
    if [ "$apply" = 0 ]; then
        echo "(dry-run — pass --apply to act; --days N sets the idle threshold, default 4)"
    fi
    if [ "$pressure" = 1 ]; then
      echo "pressure mode: reaped target/ of every idle-PR lane (a resumed lane pays a rebuild, nothing more — the 2026-10-23 ENOSPC x6 runbook)"
    fi
    ;;
  *)
    sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 1 ;;
esac
