#!/bin/sh
set -e
. ./build.sh

mkdir -p isodir
mkdir -p isodir/boot
mkdir -p isodir/boot/grub
ROOTDIR="$(pwd)"
cd sysroot
tar -cvf $ROOTDIR/isodir/boot/initrd.tar *
cd $ROOTDIR
cp sysroot/boot/vmspartix isodir/boot/vmspartix
cat > isodir/boot/grub/grub.cfg << EOF
menuentry "Spartix" {
	set timeout=10
	loadfont unicode
	insmod vbe
  	insmod vga
  	insmod gfxterm
	terminal_output gfxterm
	echo "Loading the vmspartix kernel"
	multiboot /boot/vmspartix
	echo "done."
	set gfxpayload=1024x768x32
	echo "Loading the initrd"
	module    /boot/initrd.tar
	echo "done."
	boot
}
EOF
<<<<<<< Updated upstream
grub2-mkrescue -o Spartix.iso isodir # Change this acording to your distro/OS.
=======
grub2-mkrescue -o Spartix.iso isodir
>>>>>>> Stashed changes
