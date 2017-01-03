
#!/bin/sh
set -e
. ./build.sh

mkdir -p isodir
mkdir -p isodir/boot
mkdir -p isodir/boot/grub
ROOTDIR="$(pwd)"
echo "Generating Packages..."
rm -rf sysroot/usr/include/acpica
mkdir -p $ROOTDIR/sysroot/pkg
tar -cvf $ROOTDIR/sysroot/pkg/devel.tar sysroot/usr/include
xz -9 -e -f $ROOTDIR/sysroot/pkg/devel.tar
rm -rf $ROOTDIR/sysroot/usr/include
tar -cvf $ROOTDIR/sysroot/pkg/libs-devel.tar sysroot/usr/lib
xz -9 -e -f $ROOTDIR/sysroot/pkg/libs-devel.tar
rm -f $ROOTDIR/sysroot/usr/lib/*
echo "Generating initrd..."
echo "Copying the kernel to the isodir"
cp sysroot/boot/vmspartix isodir/boot/vmspartix
rm -f sysroot/boot/vmspartix
tar -cvf $ROOTDIR/isodir/boot/initrd.tar sysroot
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
	insmod all_video
  	insmod xzio
	insmod gzio
  	insmod gfxterm
	terminal_output gfxterm
	echo "Loading the vmspartix kernel"
	multiboot2 /boot/vmspartix.xz --root=/dev/hda1
	echo "done."
	set gfxpayload=1024x768x32
	echo "Loading the initrd"
	module2 /boot/initrd.tar.xz
	echo "done."
	boot
}
EOF
#grub2-file --is-x86-multiboot2 kernel/vmspartix-0.1-gen64
grub2-mkrescue -o Spartix.iso isodir # Change this acording to your distro/OS.
