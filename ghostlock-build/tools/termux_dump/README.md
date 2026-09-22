# Termux Boot Partition Dumper

Dumps the currently active `boot` partition from a rooted Android phone,
directly on-device via Termux. Useful to grab `boot.img` for kernel-offset
extraction without needing OEM firmware packages.

## Requirements

- Device must be **rooted** (Magisk or similar) — reading raw block devices
  under `/dev/block/` needs root.
- Termux installed, with root access granted to Termux (`su` binary works
  when run from Termux).

## Usage

```bash
cd ghostlock-build/tools/termux_dump
bash dump_boot.sh
```

Output: `boot_dump.img` in the current directory (also left at
`/sdcard/boot_dump.img`).

## If auto-detection fails

List the actual partition names on your device and dump manually:

```bash
su -c 'ls -la /dev/block/bootdevice/by-name/' | grep -i boot
su -c 'dd if=/dev/block/bootdevice/by-name/<your_boot_partition> of=/sdcard/boot_dump.img bs=4M'
```

## Next step

Pull `boot_dump.img` off the device (or copy from `/sdcard/`) and run the
extractor against it:

```bash
./ghostlock-extract boot_dump.img --format c --name "<device_name>" --out offsets.h
```

Exit code `6` / a message containing "rtmutex UAF fix is present" means the
kernel is patched and GhostLock cannot be built for that device — this is a
fact about the kernel, not something a different dump method changes.
