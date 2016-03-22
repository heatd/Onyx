#!/bin/sh
set -e
. ./headers.sh

for PROJECT in $PROJECTS; do
  DESTDIR="$PWD/sysroot" $MAKE -C $PROJECT install
done
i686-spartix-nm kernel/vmspartix > Kernel.map
i686-spartix-nm -C kernel/vmspartix > Kernel-demang.map
cp Kernel.map sysroot/boot/Kernel.map
cp Kernel-demang.map sysroot/boot/Kernel-demang.map
