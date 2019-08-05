#!/bin/sh

mkdir -p $DESTDIR/etc
mkdir -p $DESTDIR/usr
mkdir -p $DESTDIR/usr/bin
mkdir -p $DESTDIR/usr/lib
mkdir -p $DESTDIR/home
mkdir -p $DESTDIR/dev
mkdir -p $DESTDIR/proc
mkdir -p $DESTDIR/sys
mkdir -p $DESTDIR/sbin
mkdir -p $DESTDIR/usr/lib/modules

cp modules.load $DESTDIR/etc/modules.load
cp hostname $DESTDIR/etc/hostname
cp passwd $DESTDIR/etc/passwd
cp fstab $DESTDIR/etc/fstab

cp $SYSTEM_ROOT/usr/bin/dash  $DESTDIR/usr/bin
cp $SYSTEM_ROOT/sbin/init     $DESTDIR/sbin
cp $SYSTEM_ROOT/usr/lib/libc.so   $DESTDIR/usr/lib
cp $SYSTEM_ROOT/usr/lib/modules/* $DESTDIR/usr/lib/modules
cp $SYSTEM_ROOT/usr/lib/ld-onyx.so   $DESTDIR/usr/lib

toolchain=$(dirname `which $HOST-gcc`)/..

./scripts/install_gcc_slibs.sh $toolchain $DESTDIR
# libstdc++ is very big and bloated and doesn't have a place in the initrd
rm -f $DESTDIR/usr/lib/libstdc++*