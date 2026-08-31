#!/usr/bin/env bash
# local-tests.sh — manual local test orchestration for conwrt.
#
# Runs the test layers that GitHub CI cannot (QEMU OpenWrt VM integration,
# bufferbloat benchmark, hardware e2e) on THIS machine, on demand.
# No scheduling, no publishing: results land in test-results/ (gitignored).
#
# Usage:
#   scripts/local-tests.sh integration          # full QEMU VM suite (tests/integration)
#   scripts/local-tests.sh bench                # bufferbloat before/after-SQM benchmark
#   scripts/local-tests.sh e2e                  # hardware tests (needs CONWRT_DEVICE_IP)
#
# Bench knobs (env): BENCH_DURATION (default 20s), BENCH_RATE_CAP (default 20M),
#                    BENCH_DOWNLOAD_KBPS (10000), BENCH_UPLOAD_KBPS (5000)
#
# First run of integration downloads the OpenWrt image and prepares it with
# sudo (loop-mount) — you will be prompted for your password.
#
# conwrt's VM tests reach the VM via `ssh root@127.0.0.1`, which requires a
# ~/.ssh/config entry (checked at preflight):
#   Host 127.0.0.1
#       Port 2222
#       IdentityFile <repo>/tests/integration/.vm_ssh_key
#       StrictHostKeyChecking no
#       UserKnownHostsFile /dev/null
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RESULTS_ROOT="test-results"
VM_IMAGE="tests/integration/.openwrt.img"
VM_KEY="tests/integration/.vm_ssh_key"
SSH_PORT=2222
STAMP="$(date +%Y%m%d-%H%M%S)"

log()  { printf '[local-tests] %s\n' "$*"; }
die()  { printf '[local-tests] ERROR: %s\n' "$*" >&2; exit 1; }

new_run_dir() {
    local dir="$RESULTS_ROOT/$1-$STAMP"
    mkdir -p "$dir"
    printf '%s\n' "$dir"
}

record_history() {  # $1=name $2=dir $3=status $4=summary
    mkdir -p "$RESULTS_ROOT"
    if [ ! -f "$RESULTS_ROOT/history.md" ]; then
        printf '| when (UTC) | suite | status | detail |\n|---|---|---|---|\n' > "$RESULTS_ROOT/history.md"
    fi
    printf '| %s | %s | %s | %s |\n' "$(date -u +%FT%TZ)" "$1" "$3" "[$4]($(basename "$2"))" >> "$RESULTS_ROOT/history.md"
}

write_index() {  # $1=dir $2=name $3=status $4=summary
    {
        printf '# %s — %s\n\n' "$2" "$3"
        printf -- '- date: %s\n- status: %s\n- %s\n\n' "$(date -u +%FT%TZ)" "$3" "$4"
        printf '## files\n\n'
        find "$1" -maxdepth 1 -type f -printf '- %f\n' | sort
    } > "$1/index.md"
}

kill_stale_vm() {
    local pids
    pids="$(pgrep -f "qemu-system-x86_64.*hostfwd=tcp::${SSH_PORT}-:22" || true)"
    if [ -n "$pids" ]; then
        log "killing stale QEMU VM holding port $SSH_PORT (pid: $pids)"
        # shellcheck disable=SC2086
        kill $pids 2>/dev/null || true
        sleep 1
    fi
}

vm_explicit_ssh_ok() {  # reach the VM with explicit port/key (no ~/.ssh/config needed)
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR \
        -i "$VM_KEY" -p "$SSH_PORT" root@127.0.0.1 true 2>/dev/null
}

vm_default_ssh_ok() {  # exactly what conwrt does: relies on ~/.ssh/config entry
    ssh -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR root@127.0.0.1 true 2>/dev/null
}

require_ssh_config_entry() {
    if ssh -G root@127.0.0.1 2>/dev/null | grep -qE '^port 2222$'; then
        return 0
    fi
    die "conwrt reaches the VM via 'ssh root@127.0.0.1' — add this to ~/.ssh/config first:

    Host 127.0.0.1
        Port 2222
        IdentityFile ${REPO_ROOT}/${VM_KEY}
        StrictHostKeyChecking no
        UserKnownHostsFile /dev/null
"
}

boot_vm() {
    kill_stale_vm
    [ -f "$VM_IMAGE" ] || die "VM image missing — run 'scripts/local-tests.sh integration' once first (downloads + prepares it; sudo prompted)"
    [ -f "$VM_KEY" ]   || die "VM SSH key missing — run 'integration' once first"
    require_ssh_config_entry

    local kvm_args=()
    if [ -w /dev/kvm ]; then
        kvm_args=(-enable-kvm -cpu host)
    else
        log "WARNING: /dev/kvm not writable — VM will boot in TCG emulation (very slow)"
    fi

    qemu-system-x86_64 \
        -drive "file=$VM_IMAGE,format=raw,if=virtio" \
        -m 512M \
        -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22" \
        -device virtio-net-pci,netdev=net0 \
        -display none \
        -serial file:tests/integration/.serial.log \
        -daemonize \
        "${kvm_args[@]}"

    log "VM booted — waiting for SSH (up to 5 min)"
    local i
    for i in $(seq 1 60); do
        if vm_explicit_ssh_ok; then
            log "VM SSH ready (~$((i * 5))s)"
            return 0
        fi
        sleep 5
    done
    die "VM never became SSH-reachable — serial log tail: tests/integration/.serial.log"
}

junit_summary() {  # $1=junit.xml
    python3 - "$1" <<'PYEOF'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
s = root if root.tag == "testsuite" else root.find("testsuite")
if s is None:
    for ts in root.iter("testsuite"):
        s = ts
        break
print(f"{s.get('tests', '?')} tests, {s.get('failures', '?')} failures, "
      f"{s.get('errors', '?')} errors, {s.get('skipped', '?')} skipped")
PYEOF
}

run_integration() {
    command -v qemu-system-x86_64 >/dev/null 2>&1 || die "qemu-system-x86_64 not installed"
    kill_stale_vm
    require_ssh_config_entry
    if [ ! -f "$VM_IMAGE" ]; then
        log "VM image not cached — first run downloads it and prepares with sudo (password prompt)"
    fi

    local dir status summary
    dir="$(new_run_dir integration)"
    log "running tests/integration (QEMU OpenWrt VM suite) → $dir"

    status=FAIL
    if python3 -m pytest tests/integration -v --junitxml="$dir/junit.xml" 2>&1 | tee "$dir/pytest.log"; then
        status=PASS
    fi
    summary="$(junit_summary "$dir/junit.xml" 2>/dev/null || echo 'see pytest.log')"

    kill_stale_vm  # pytest tears down its own VM; this catches crashed runs
    write_index "$dir" integration "$status" "$summary"
    record_history integration "$dir" "$status" "$summary"
    log "$status — $summary ($dir)"
    [ "$status" = PASS ]
}

run_bench() {
    command -v qemu-system-x86_64 >/dev/null 2>&1 || die "qemu-system-x86_64 not installed"
    command -v iperf3 >/dev/null 2>&1 || die "iperf3 not installed on host"

    local dir status summary
    dir="$(new_run_dir bench)"
    local duration="${BENCH_DURATION:-20}" rate="${BENCH_RATE_CAP:-20M}"
    local dl="${BENCH_DOWNLOAD_KBPS:-10000}" ul="${BENCH_UPLOAD_KBPS:-5000}"
    summary="bufferbloat duration=${duration}s rate=$rate sqm=${dl}/${ul}kbps"

    boot_vm
    trap kill_stale_vm EXIT

    log "running bufferbloat benchmark → $dir"
    status=FAIL
    if python3 tests/integration/run_bufferbloat_test.py \
        --host 127.0.0.1 --port "$SSH_PORT" --key "$VM_KEY" \
        --conwrt-repo "$REPO_ROOT" --output-dir "$dir" \
        --duration "$duration" --rate-cap "$rate" \
        --download-kbps "$dl" --upload-kbps "$ul" 2>&1 | tee "$dir/bench.log"; then
        status=PASS
    fi

    kill_stale_vm
    trap - EXIT
    write_index "$dir" bench "$status" "$summary"
    record_history bench "$dir" "$status" "$summary"
    log "$status — $summary ($dir)"
    [ "$status" = PASS ]
}

run_e2e() {
    [ -n "${CONWRT_DEVICE_IP:-}" ] || die "CONWRT_DEVICE_IP not set — hardware e2e needs a reachable router (see tests/e2e/conftest.py)"

    local dir status summary
    dir="$(new_run_dir e2e)"
    log "running hardware e2e against $CONWRT_DEVICE_IP → $dir"

    status=FAIL
    if python3 -m pytest tests/e2e -v --junitxml="$dir/junit.xml" 2>&1 | tee "$dir/pytest.log"; then
        status=PASS
    fi
    summary="$(junit_summary "$dir/junit.xml" 2>/dev/null || echo 'see pytest.log')"

    write_index "$dir" e2e "$status" "$summary"
    record_history e2e "$dir" "$status" "$summary"
    log "$status — $summary ($dir)"
    [ "$status" = PASS ]
}

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

case "${1:-}" in
    integration) run_integration ;;
    bench)       run_bench ;;
    e2e)         run_e2e ;;
    *)           usage ;;
esac
