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
cp shadow $DESTDIR/etc/shadow
cp profile $DESTDIR/etc/profile

# TODO: use the cross-toolchain's strip
cp $SYSTEM_ROOT/usr/bin/dash  $DESTDIR/usr/bin
cp $SYSTEM_ROOT/sbin/init     $DESTDIR/sbin
cp $SYSTEM_ROOT/usr/lib/libc.so   $DESTDIR/usr/lib
strip -g --strip-unneeded $DESTDIR/usr/lib/libc.so
strip -g --strip-all $DESTDIR/usr/bin/dash
strip -g --strip-all $DESTDIR/sbin/init
#du -smh $DESTDIR/usr/lib/libc.so
#du -smh $DESTDIR/usr/bin/dash
cp $SYSTEM_ROOT/usr/lib/modules/* $DESTDIR/usr/lib/modules
#strip -g --strip-unneeded $DESTDIR/usr/lib/modules/*.ko
#du -smh $DESTDIR/usr/lib/modules/*.ko
ln -sf libc.so $DESTDIR/usr/lib/ld-onyx.so

toolchain=$(dirname `which $HOST-gcc`)/..

./scripts/install_gcc_slibs.sh $toolchain $DESTDIR
# strip libgcc_s.so
strip -g --strip-unneeded $DESTDIR/usr/lib/libgcc_s.so.1
#du -smh $DESTDIR/usr/lib/libgcc_s.so.1

# libstdc++ is very big and bloated and doesn't have a place in the initrd
rm -f $DESTDIR/usr/lib/libstdc++*
