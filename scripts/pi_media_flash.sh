#!/usr/bin/env bash
# Flash a Raspberry Pi OS image onto removable media, then seed the boot FAT
# with headless cloud-init config and an EEPROM update package — no mounting.
#
# Usage:   sudo bash scripts/pi_media_flash.sh /dev/sdX
# Env:     IMG  image to write            (default: seedling raspios64-lite)
#          UD   cloud-init user-data file (default: /tmp/opencode/pi-user-data)
#          KIT  rescue-kit dir providing  recovery.bin / pieeprom.upd /
#               pieeprom.sig              (default: ~/pi-rescue-kit)
#
# Exit codes: 0 written+verified+seeded; 3 written but VERIFY-FAIL (run the
# 4K repair, see recipes/raspberry-pi/laptop-direct-lab.md § flashing);
# 1 refused or errored.
#
# Traps encoded here, each hit live on 2026-11-20 — see
# recipes/raspberry-pi/laptop-direct-lab.md:
#   * udisks auto-mounts AND re-mounts; unmount partitions yourself and
#     never partprobe (mtools needs no kernel partitions — raw @@offset).
#   * sudo's $HOME is /root; resolve the caller's home from SUDO_USER.
#   * mcopy -n STILL prompts on existing targets (hangs on closed stdin):
#     mdel first. mtools 4.0.49 mdel has no -s flag; guard the rc.
#   * the raspios image ships its own cloud-init seed — ours overwrites it.
set -euo pipefail

DEV="${1:?usage: pi_media_flash.sh /dev/sdX}"
REAL_HOME=$(getent passwd "${SUDO_USER:-$(logname 2>/dev/null || echo user)}" | cut -d: -f6)
IMG="${IMG:-$REAL_HOME/src/seedling-m1/pi/raspios64-lite.img}"
UD="${UD:-/tmp/opencode/pi-user-data}"
KIT="${KIT:-$REAL_HOME/pi-rescue-kit}"
for f in "$IMG" "$UD" "$KIT/recovery.bin" "$KIT/pieeprom.upd" "$KIT/pieeprom.sig"; do
  [ -f "$f" ] || { echo "missing input: $f"; exit 1; }
done

# --- safety gates ---
[ -b "$DEV" ] || { echo "no such block device: $DEV"; exit 1; }
info=$(lsblk -dn -o RM,TRAN,SIZE "$DEV")
grep -q '^1 usb' <<<"$info" || {
  echo "REFUSE: $DEV is not a removable USB device:"; echo "$info"; exit 1; }

# udisks auto-mounts and RE-mounts partitions; disk-level lsblk cannot see
# partition mounts, so walk /sys and unmount until quiet.
base=$(basename "$DEV")
unmount_target() {
  local mp pd part
  for part in /sys/block/"$base"/"$base"?*; do
    [ -d "$part" ] || continue
    pd="/dev/${part##*/}"
    mp=$(lsblk -nrno MOUNTPOINTS "$pd" 2>/dev/null || true)
    if [ -n "$mp" ]; then
      echo "  unmounting $pd ($mp)"
      udisksctl unmount -b "$pd" >/dev/null 2>&1 || umount "$pd" || umount -l "$pd"
    fi
  done
}
unmount_target
sleep 1
unmount_target
if [ -n "$(lsblk -nrno MOUNTPOINTS "$DEV")" ]; then
  echo "REFUSE: partitions still mounted after unmount attempts"; exit 1
fi

echo "== target: $DEV $(lsblk -dn -o VENDOR,MODEL,SIZE "$DEV")"
echo "  partitions on it:"; lsblk -l "$DEV" | tail -n +2 || true
read -rp "type YES to wipe $DEV completely: " a
[ "$a" = YES ] || { echo "aborted"; exit 1; }

echo "== dd $(du -h "$IMG" | cut -f1) ..."
sudo dd if="$IMG" of="$DEV" bs=4M status=progress conv=fsync
# NOTE: deliberately NO partprobe — re-reading the table is what makes udisks
# re-mount the fresh partitions behind our back. mtools below addresses the
# device by raw byte offset and does not need kernel partitions.

echo "== verify written bytes (cache-evicted) =="
size=$(stat -c%s "$IMG")
readback=$(sudo sh -c "blockdev --flushbufs $DEV; head -c $size $DEV" \
           | sha256sum | cut -d' ' -f1)
expect=$(sha256sum "$IMG" | cut -d' ' -f1)
echo "    image:    $expect"
echo "    readback: $readback"
if [ "$readback" != "$expect" ]; then
  echo "VERIFY-FAIL: bytes on $DEV differ from the image — run the 4K repair"
  exit 3
fi
echo "VERIFY-OK"

echo "== seed bootfs (mtools, no mount) =="
start=$(cat "/sys/block/$base/${base}1/start" 2>/dev/null || true)
[ -n "$start" ] || start=$(sfdisk -d "$DEV" | awk '/start=/{print $4; exit}' | tr -d ',')
off=$(( start * 512 ))
echo "  bootfs at sector $start (byte offset $off)"
for f in user-data recovery.bin pieeprom.upd pieeprom.sig; do
  sudo mdel -i "$DEV@@$off" ::"$f" 2>/dev/null || true
done
sudo mcopy -i "$DEV@@$off" "$UD" ::user-data
for f in recovery.bin pieeprom.upd pieeprom.sig; do
  sudo mcopy -i "$DEV@@$off" "$KIT/$f" ::"$f"
done
sync
sudo blockdev --flushbufs "$DEV"

echo "== bootfs now =="
sudo mdir -i "$DEV@@$off" :: | tail -12
echo "== seed sanity (first lines of user-data) =="
sudo mtype -i "$DEV@@$off" ::user-data | head -3
echo "DONE. Flush complete — safe to pull and move to the Pi."
