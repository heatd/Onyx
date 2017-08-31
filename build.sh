#!/bin/sh
set -e
. ./headers.sh

for PROJECT in $PROJECTS; do
  echo Building $PROJECT
  DESTDIR="$PWD/sysroot" $MAKE -C $PROJECT install -s
done
for PACKAGE in $SOURCE_PACKAGES; do
  echo Building $PACKAGE
  DESTDIR="$PWD/sysroot" $MAKE -C $PACKAGE install
done

./utils/make_utils.sh install
DESTDIR="$PWD/sysroot" ./build_dash.sh
./build_packages.sh
$NM kernel/vmonyx > Kernel.map
cp Kernel.map sysroot/boot/Kernel.map
mkdir -p $PWD/sysroot/sbin
