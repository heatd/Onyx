#!/bin/sh
# Copyright (c) 2021 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#
# SPDX-License-Identifier: MIT
#
set -e
TEMP=$(getopt -o 'l:h' --long 'size:,no-disk,help,bootable:' -n 'create_disk_image.sh' -- "$@")

eval set -- "$TEMP"

unset TEMP

print_help()
{
    echo "Usage: create_disk_image.sh [OPTIONS] image-name"
    echo "Create a disk image for Onyx, with a proper system."
    echo "Installs everything that is under sysroot/, onto the filesystem's /."
    echo "Options:"
    echo "  -l, --size=SIZE             Size, in human units, of the disk image to build. If \'adaptive\', try to auto-detect the size."
    echo "                              Defaults to adaptive."
    echo "  --no-disk                   Just create a partition image, and not a whole disk."
    echo "  --bootable=TYPE             Create a bootable disk image of type TYPE (e.g EFI or BIOS), with GRUB 2 installed."
    echo "  -h, --help                  Show this help message."
}

size="adaptive"
no_disk=0
fs_type="ext2"
bootable=

while true; do
	case "$1" in
		'-l'|'--size')
            size=$2
            shift 2
        ;;
        '--no-disk')
            no_disk=1
            shift
        ;;
        '-h'|'--help')
            print_help
            exit 0
        ;;
        '--bootable')
            bootable=$2
            shift 2
        ;;
        '--')
			shift
			break
		;;
	esac
done

if [ "$#" -ne "1" ]; then
	echo "create_disk_image.sh: Bad usage"
    print_help
	exit 1
fi

image_name=$1
part_name="${image_name}.part"

rm -f "$part_name"

./scripts/create_standard_fs.sh new_fs --no-strip

if [ "$size" = "adaptive" ]; then
    ./scripts/create_adaptive_disk_image.py "$(du -s new_fs/ | cut -f1)" "$part_name"
else
    fallocate -l "$size" "$part_name"
fi

mkdir -p new_fs/boot/grub
cp initrd.tar.xz new_fs/boot/
cat >> new_fs/boot/grub/grub.cfg << EOF
    menuentry "Onyx" {
	loadfont unicode
	insmod all_video
  	insmod xzio
  	insmod gfxterm
	terminal_output gfxterm
	set gfxpayload=1024x768x32

	echo "Loading the vmonyx kernel"
	multiboot2 /boot/vmonyx --root=/dev/sda2
    module2 /boot/initrd.tar.xz

	boot
    }
EOF

if [ "$bootable" = "efi" ]; then
    sed -i -e 's/sda1/sda2/g' new_fs/etc/fstab
fi

# mkfs has a confirmation prompt, so we need the yes
yes | mkfs.$fs_type -t $fs_type -L "Onyx.root" -d new_fs "$part_name"

if [ "$no_disk" = "0" ]; then
    gpt_blocks="20"
    part_size=$(stat -c %s "$part_name")
    nr_blocks=$((part_size / 1024 + gpt_blocks))
    onyx_root_start_mb="1"

    if [ "$bootable" = "efi" ]; then
        ./scripts/build_grub_efi_image.sh
        onyx_root_start_mb=$((onyx_root_start_mb + 10))
        fallocate -l 10MiB esp.part
        mkfs.fat -n "ESP" esp.part
        mmd -i esp.part EFI
        mmd -i esp.part EFI/BOOT
        mcopy -i esp.part bootx64.efi ::/EFI/BOOT

        rm bootx64.efi
        EXTRA_PARTITIONS="$EXTRA_PARTITIONS mkpart \"EFI System Partition\" fat32 1MiB 11MiB set 1 esp on"
    fi

    echo "Enlarging the disk to $nr_blocks blocks"
    # Reserve the GPT space at the start and end of the disk image, for GPT
    # Should be plenty of GPT space for everyone :)
    # Note that we need to start at 1MiB for optimal alignment
    fallocate -l "${nr_blocks}KiB" "$part_name"
    fallocate -i -l ${onyx_root_start_mb}MiB "$part_name"

    parted "$part_name" -- \
    mktable gpt \
    "$EXTRA_PARTITIONS" \
    mkpart "Onyx.root" $fs_type ${onyx_root_start_mb}MiB 100%

    if [ "$bootable" = "efi" ]; then
        dd if=esp.part of=$part_name bs=1MiB seek=1 count=10 conv=notrunc
        rm esp.part
    fi
fi

mv "$part_name" "$image_name"
rm -rf new_fs
