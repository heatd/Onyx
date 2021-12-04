#!/bin/sh
set -e

mkdir -p isodir
mkdir -p isodir/boot
mkdir -p isodir/boot/grub

SYSTEM_ROOT=$DESTDIR scripts/geninitrd scripts/default-initrd.sh

cp sysroot/boot/vmonyx isodir/boot/vmonyx
INITRD_NAME=initrd.tar.xz
cp $INITRD_NAME isodir/boot

echo "Compressing kernel"
xz -9 -e -f isodir/boot/vmonyx

cat > isodir/boot/grub/grub.cfg << EOF
menuentry "Onyx" {
	loadfont unicode
	insmod all_video
  	insmod xzio
  	insmod gfxterm
	terminal_output gfxterm
	set gfxpayload=1024x768x32

	echo "Loading the vmonyx kernel"
	multiboot2 /boot/vmonyx.xz --root=/dev/sda1
	echo "Loading the initrd"
	module2 /boot/${INITRD_NAME}

	boot
}
EOF
grub-mkrescue -o Onyx.iso isodir # Change this acording to your distro/OS.
