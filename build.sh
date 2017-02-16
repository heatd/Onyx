#!/bin/sh
set -e
. ./headers.sh

for PROJECT in $PROJECTS; do
  DESTDIR="$PWD/sysroot" $MAKE -C $PROJECT install -s
done

for PACKAGE in $SOURCE_PACKAGES; do
  DESTDIR="$PWD/sysroot" $MAKE -C $PACKAGE install -s
done
x86_64-spartix-nm kernel/vmonyx > Kernel.map
cp Kernel.map sysroot/boot/Kernel.map
sha256sum kernel/vmonyx > vmonyx.sha256
mkdir -p $PWD/sysroot/sbin
cp vmonyx.sha256 $PWD/sysroot/sbin/vmonyx.checksum
