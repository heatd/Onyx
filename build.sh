#!/bin/sh
set -e
. ./headers.sh

for PROJECT in $PROJECTS; do
  echo Building $PROJECT
  DESTDIR="$PWD/sysroot" $MAKE -C $PROJECT install -s
done

for PACKAGE in $SOURCE_PACKAGES; do
  echo Building $PACKAGE
  DESTDIR="$PWD/sysroot" $MAKE -C $PACKAGE install -s
done

./build_packages.sh
$NM kernel/vmonyx > Kernel.map
cp Kernel.map sysroot/boot/Kernel.map
sha256sum kernel/vmonyx > vmonyx.sha256
mkdir -p $PWD/sysroot/sbin
cp vmonyx.sha256 $PWD/sysroot/sbin/vmonyx.checksum
