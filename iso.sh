#!/bin/sh
set -e
. ./build.sh

mkdir -p isodir
mkdir -p isodir/boot
mkdir -p isodir/boot/grub
ROOTDIR="$(pwd)"
cd sysroot
echo "Generating initrd"
tar -cvf $ROOTDIR/isodir/boot/initrd.tar *
cd $ROOTDIR
echo "Copying the kernel to the isodir"
cp sysroot/boot/vmspartix isodir/boot/vmspartix
echo "Compressing kernel and initrd images"
xz -9 -e -f isodir/boot/vmspartix
xz -9 -e -f isodir/boot/initrd.tar
echo "Testing the initrd and kernel integrity"
xz -t isodir/boot/vmspartix.xz
xz -t isodir/boot/initrd.tar.xz
cat > isodir/boot/grub/grub.cfg << EOF
menuentry "Spartix" {
	set timeout=10
	loadfont unicode
	insmod vbe
  	insmod vga
  	insmod xzio
	insmod gzio
  	insmod gfxterm
	terminal_output gfxterm
	echo "Loading the vmspartix kernel"
	multiboot /boot/vmspartix.xz
	echo "done."
	set gfxpayload=1024x768x32
	echo "Loading the initrd"
	module    /boot/initrd.tar.xz
	echo "done."
	boot
}
EOF
grub2-mkrescue -o Spartix.iso isodir # Change this acording to your distro/OS.
