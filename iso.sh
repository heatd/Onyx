#!/bin/sh
set -e
. ./build.sh

mkdir -p isodir
mkdir -p isodir/boot
mkdir -p isodir/boot/grub

cp sysroot/boot/vmspartix isodir/boot/vmspartix
cat > isodir/boot/grub/grub.cfg << EOF
menuentry "Spartix" {
	multiboot /boot/vmspartix
}
EOF
grub-mkrescue -o myos.iso isodir
