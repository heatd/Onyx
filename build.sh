#!/bin/sh
set -e
. ./headers.sh

for PROJECT in $PROJECTS; do
  DESTDIR="$PWD/sysroot" $MAKE -C $PROJECT install -s
done

for PACKAGE in $SOURCE_PACKAGES; do
  DESTDIR="$PWD/sysroot" $MAKE -C $PACKAGE install -s
done
mkdir -p sysroot/etc/
cat > sysroot/etc/fstab << EOF
/dev/sda1     /

EOF
x86_64-spartix-nm kernel/vmspartix > Kernel.map
cp Kernel.map sysroot/boot/Kernel.map
sha256sum kernel/vmspartix > vmspartix.sha256
mkdir -p $PWD/sysroot/sbin
cp vmspartix.sha256 $PWD/sysroot/sbin/vmspartix.checksum
