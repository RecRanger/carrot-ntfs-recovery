#!/usr/bin/env bash

# Bash script to generate a 1 GiB filesystem
# in a dd-compatible drive image file with an ntfs filesystem.
# Writes a few small files, and a few 100 MiB files.

set -euo pipefail
set -x


# Arguments.
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <output-image-file>"
    exit 1
fi

IMAGE="$1"

# Configuration.
SIZE_MIB=1024
MOUNT_DIR="$(mktemp -d)"
LABEL="TEST_NTFS"

# Ensure cleanup on exit or error
cleanup() {
    set +e
    mountpoint -q "$MOUNT_DIR" && umount "$MOUNT_DIR"
    losetup -D 2>/dev/null || true
    rmdir "$MOUNT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Create a 1 GiB sparse image file
dd if=/dev/zero of="$IMAGE" bs=1M count="$SIZE_MIB" status=progress

# Create an NTFS filesystem
mkfs.ntfs -F -L "$LABEL" "$IMAGE"

# Attach image to a loop device
LOOP_DEV="$(losetup --find --show "$IMAGE")"

# Mount it
mount -t ntfs-3g "$LOOP_DEV" "$MOUNT_DIR"

# Write a few small files
echo "Hello, NTFS!" > "$MOUNT_DIR/hello.txt"
date > "$MOUNT_DIR/date.txt"
echo "Taunt-Change-Blatancy-Brunch-Procurer Darn-Gainfully-Skied-Passive-Pancake" > "$MOUNT_DIR/sample_password.txt"
dd if=/dev/urandom of="$MOUNT_DIR/small_random.bin" bs=1 count=25 status=progress

# Write a few ~100 MiB files
dd if=/dev/urandom of="$MOUNT_DIR/bigfile1.bin" bs=1M count=100 status=progress
dd if=/dev/urandom of="$MOUNT_DIR/bigfile2.bin" bs=1M count=100 status=progress
dd if=/dev/urandom of="$MOUNT_DIR/bigfile3.bin" bs=1M count=100 status=progress

FOLDER_1="$MOUNT_DIR/folder1"
mkdir "$FOLDER_1"
echo "Sample file in folder1" > "$FOLDER_1/sample_file.txt"

FOLDER_1_SUBFOLDER="$FOLDER_1/subfolder_in_folder1"
mkdir "$FOLDER_1_SUBFOLDER"
echo "Sample file in subfolder_in_folder1" > "$FOLDER_1_SUBFOLDER/sample_file.txt"

# Ensure all data is flushed
sync

# Unmount and detach handled by trap.
