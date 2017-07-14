#!/bin/sh
set -e
. ./build.sh

mkdir -p isodir
mkdir -p isodir/boot
mkdir -p isodir/boot/grub
ROOTDIR="$(pwd)"
cp modules.load sysroot/etc/modules.load
cp hostname sysroot/etc/hostname
cp passwd sysroot/etc/passwd
cp fstab sysroot/etc/fstab
echo "Generating Packages..."
rm -rf sysroot/usr/include/acpica
mkdir -p $ROOTDIR/sysroot/pkg
tar -cvf $ROOTDIR/sysroot/pkg/devel.tar sysroot/usr/include
xz -9 -e -f $ROOTDIR/sysroot/pkg/devel.tar
tar -cvf $ROOTDIR/sysroot/pkg/libs-devel.tar sysroot/usr/lib
rm -rf $ROOTDIR/sysroot/usr/include
xz -9 -e -f $ROOTDIR/sysroot/pkg/libs-devel.tar
echo "Generating initrd..."
echo "Copying the kernel to the isodir"
cp sysroot/boot/vmonyx isodir/boot/vmonyx
rm -f sysroot/boot/vmonyx
mkdir -p $ROOTDIR/sysroot/lib
cp -rv $ROOTDIR/sysroot/usr/lib $ROOTDIR/sysroot/
tar -cvf $ROOTDIR/isodir/boot/initrd.tar sysroot
rm -rf sysroot/lib
echo "Compressing kernel and initrd images"
xz -9 -e -f isodir/boot/vmonyx
xz -9 -e -f isodir/boot/initrd.tar
echo "Testing the initrd and kernel integrity"
xz -t isodir/boot/vmonyx.xz
xz -t isodir/boot/initrd.tar.xz
cat > isodir/boot/grub/grub.cfg << EOF
menuentry "Onyx" {
	set timeout=10
	loadfont unicode
	insmod all_video
  	insmod xzio
	insmod gzio
  	insmod gfxterm
	terminal_output gfxterm
	echo "Loading the vmonyx kernel"
	multiboot2 /boot/vmonyx.xz --root=/dev/hda1
	echo "done."
	set gfxpayload=1024x768x32
	echo "Loading the initrd"
	module2 /boot/initrd.tar.xz
	echo "done."
	boot
}
EOF
#grub2-file --is-x86-multiboot2 kernel/vmonyx-0.1-gen64
grub2-mkrescue -o Onyx.iso isodir # Change this acording to your distro/OS.
