#!/bin/sh
set -e

mkdir -p isodir
mkdir -p isodir/boot
mkdir -p isodir/boot/grub

INITRD_GEN_SCRIPT=$1

if [ "$INITRD_GEN_SCRIPT" = "" ]; then
	INITRD_GEN_SCRIPT="scripts/default-initrd.sh"
fi

SYSTEM_ROOT=$DESTDIR scripts/geninitrd "$INITRD_GEN_SCRIPT"

cp sysroot/boot/vmonyx isodir/boot/vmonyx
INITRD_NAME=initrd.tar.zst
cp $INITRD_NAME isodir/boot

echo "Compressing kernel"
xz -9 -e -f isodir/boot/vmonyx
#zstd -15 isodir/boot/vmonyx

if [ "$INTEL_UCODE" != "" ]; then
    INTEL_UCODE_CMD="module2 /boot/$(basename $INTEL_UCODE)"
    cp $INTEL_UCODE isodir/boot
fi

cat >isodir/boot/grub/grub.cfg <<EOF
set default="0"
set timeout=5
menuentry "Onyx" {
    loadfont unicode
    insmod all_video
    insmod xzio
    insmod gfxterm
    terminal_output gfxterm
    set gfxpayload=1024x768x32

    echo "Loading the vmonyx kernel"
    multiboot2 /boot/vmonyx.xz --root=/dev/nvme0n1p1
    echo "Loading the initrd"
    module2 /boot/${INITRD_NAME}
    ${INTEL_UCODE_CMD}
    ${AMD_UCODE_CMD}

    boot
}
EOF

GRUB_MKRESCUE=""

if command -v grub-mkrescue; then
	GRUB_MKRESCUE="grub-mkrescue"
elif command -v grub2-mkrescue; then
	GRUB_MKRESCUE="grub2-mkrescue"
else
	echo "grub-mkrescue not found! Please install it."
	exit 1
fi

$GRUB_MKRESCUE -o Onyx.iso isodir
