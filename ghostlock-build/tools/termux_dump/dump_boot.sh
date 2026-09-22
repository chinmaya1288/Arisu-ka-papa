#!/data/data/com.termux/files/usr/bin/bash
# Dump the active boot partition from a rooted Android device via Termux.
# Requires: root (su), Termux with `tsu` or built-in `su` access.
#
# Usage:
#   pkg install root-repo -y && pkg install tsu -y   # if su not already available
#   bash dump_boot.sh
#
# Output: ./boot_dump.img in the current directory.

set -e

OUT="${1:-boot_dump.img}"

echo "[*] Locating boot partition..."

# Try common by-name paths first (works on most Qualcomm/MTK devices)
CANDIDATES=(
  "/dev/block/bootdevice/by-name/boot_a"
  "/dev/block/bootdevice/by-name/boot"
  "/dev/block/by-name/boot_a"
  "/dev/block/by-name/boot"
)

BOOT_PATH=""
for p in "${CANDIDATES[@]}"; do
  if su -c "test -e $p"; then
    BOOT_PATH="$p"
    break
  fi
done

if [ -z "$BOOT_PATH" ]; then
  echo "[*] Not found in common paths, checking active slot via getprop..."
  SLOT=$(su -c "getprop ro.boot.slot_suffix" 2>/dev/null || echo "")
  if [ -n "$SLOT" ]; then
    for base in "/dev/block/bootdevice/by-name/boot" "/dev/block/by-name/boot"; do
      p="${base}${SLOT}"
      if su -c "test -e $p"; then
        BOOT_PATH="$p"
        break
      fi
    done
  fi
fi

if [ -z "$BOOT_PATH" ]; then
  echo "[!] Could not auto-detect boot partition path."
  echo "[!] List partitions manually with:"
  echo "    su -c 'ls -la /dev/block/bootdevice/by-name/'"
  echo "[!] Then re-run: bash dump_boot.sh <custom_path_as_arg_not_supported_yet>"
  exit 1
fi

echo "[*] Found boot partition: $BOOT_PATH"
echo "[*] Dumping to: $OUT"

su -c "dd if=$BOOT_PATH of=/sdcard/boot_dump.img bs=4M"
cp /sdcard/boot_dump.img "$OUT" 2>/dev/null || true

echo "[+] Done. File saved at: $OUT"
ls -lh "$OUT"
file "$OUT" 2>/dev/null || true
