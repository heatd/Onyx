#!/bin/sh
set -e
. ./headers.sh

for PROJECT in $PROJECTS; do
  DESTDIR="$PWD/sysroot" $MAKE -C $PROJECT install
done
export CFLAGS="$CFLAGS -lnosys"
for PACKAGE in $SOURCE_PACKAGES; do
  DESTDIR="$PWD/sysroot" $MAKE -C $PACKAGE install
done
mkdir -p sysroot/etc/
cat > sysroot/etc/fstab << EOF
/dev/sda1     /

EOF
x86_64-spartix-nm kernel/vmspartix-0.1-gen64 > Kernel.map
cp Kernel.map sysroot/boot/Kernel.map
