#!/bin/sh
set -e
. ./config.sh

for PROJECT in $PROJECTS; do
  $MAKE -C $PROJECT clean
done
for PACKAGE in $SOURCE_PACKAGES; do
  DESTDIR="$PWD/sysroot" $MAKE -C $PACKAGE clean
done
./utils/make_utils.sh clean
rm -rfv sysroot
rm -rfv isodir
rm -rfv Onyx.iso
rm -rfv Kernel.map
