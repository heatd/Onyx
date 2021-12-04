#!/bin/sh
# Copyright (c) 2021 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#
# SPDX-License-Identifier: MIT
#
set -e
TEMP=$(getopt -o 'l:h' --long 'size:,no-disk,help' -n 'create_disk_image.sh' -- "$@")

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
    echo "  -h, --help                  Show this help message."
}

size="adaptive"
no_disk=0
fs_type="ext2"

while true; do
	case "$1" in
		'-l|--size')
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

./scripts/create_standard_fs.sh new_fs

if [ "$size" = "adaptive" ]; then
    ./scripts/create_adaptive_disk_image.py "$(du -s new_fs/ | cut -f1)" "$part_name"
else
    fallocate -l "$size" "$part_name"
fi

# mkfs has a confirmation prompt, so we need the yes
yes | mkfs.$fs_type -L "Onyx.root" -d new_fs "$part_name"

if [ "$no_disk" = "0" ]; then
    gpt_blocks="20"
    part_size=$(stat -c %s "$part_name")
    nr_blocks=$(("$part_size" / 1024 + "$gpt_blocks"))
    echo "Enlarging the disk to $nr_blocks blocks"
    # Reserve the GPT space at the start and end of the disk image, for GPT
    # Should be plenty of GPT space for everyone :)
    # Note that we need to start at 1MiB for optimal alignment
    fallocate -l "${nr_blocks}KiB" "$part_name"
    fallocate -i -l 1MiB "$part_name"

    # At this moment, the root ext2 partition starts at 10KiB
    parted "$part_name" << EOF
mktable gpt
mkpart "Onyx.root" $fs_type 1MiB 100%
quit
EOF

fi

mv "$part_name" "$image_name"
rm -rf new_fs
