#!/bin/sh
set -e
. ./headers.sh

for PROJECT in $PROJECTS; do
  DESTDIR="$PWD/sysroot" $MAKE -C $PROJECT install
done
x86_64-spartix-nm kernel/vmspartix-0.1-gen64 > Kernel.map
cp Kernel.map sysroot/boot/Kernel.map
