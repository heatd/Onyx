#!/bin/sh
# Copyright (c) 2021 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#
# SPDX-License-Identifier: MIT
#

grub-mkimage -p /boot/grub -O "${ONYX_ARCH}-efi" -c scripts/grub/grub-early.cfg \
-o bootx64.efi at_keyboard boot chain configfile fat ext2 multiboot multiboot2 \
linux ls part_gpt reboot serial efi_gop efi_uga echo elf ata ahci gfxterm all_video xzio \
font multiboot
