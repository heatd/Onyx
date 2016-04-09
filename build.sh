#!/bin/sh
set -e
. ./headers.sh

for PROJECT in $PROJECTS; do
  DESTDIR="$PWD/sysroot" $MAKE -C $PROJECT install
done
i686-spartix-nm kernel/vmspartix > Kernel.map
cp Kernel.map sysroot/boot/Kernel.map
