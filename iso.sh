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
	multiboot /boot/vmspartix
	module    /boot/initrd.tar
}
EOF
grub-mkrescue -o Spartix.iso isodir
