#!/bin/sh
set -e
. ./headers.sh

cd kernel
../scripts/config_to_header.py include/onyx/config.h
cd ..

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

cp kernel/kernel.config $PWD/sysroot/boot
rm kernel/include/onyx/config.h

./build_packages.sh
$NM kernel/vmonyx > Kernel.map
cp Kernel.map sysroot/boot/Kernel.map
mkdir -p $PWD/sysroot/sbin
