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

cp defaults/modules.load $DESTDIR/etc/modules.load
cp defaults/hostname $DESTDIR/etc/hostname
cp defaults/passwd $DESTDIR/etc/passwd
cp defaults/fstab $DESTDIR/etc/fstab
cp defaults/shadow $DESTDIR/etc/shadow
cp defaults/profile $DESTDIR/etc/profile
cp defaults/resolv.conf $DESTDIR/etc/resolv.conf

cp $SYSTEM_ROOT/usr/bin/dash  $DESTDIR/usr/bin
cp $SYSTEM_ROOT/sbin/init     $DESTDIR/sbin
cp $SYSTEM_ROOT/usr/lib/libc.so   $DESTDIR/usr/lib
$STRIP -g --strip-unneeded $DESTDIR/usr/lib/libc.so
$STRIP -g --strip-all $DESTDIR/usr/bin/dash
$STRIP -g --strip-all $DESTDIR/sbin/init
#du -smh $DESTDIR/usr/lib/libc.so
#du -smh $DESTDIR/usr/bin/dash
cp $SYSTEM_ROOT/usr/lib/modules/* $DESTDIR/usr/lib/modules
#strip -g --strip-unneeded $DESTDIR/usr/lib/modules/*.ko
#du -smh $DESTDIR/usr/lib/modules/*.ko
ln -sf libc.so $DESTDIR/usr/lib/ld-onyx.so

./scripts/install_compiler_slibs.sh $DESTDIR --strip --no-c++

