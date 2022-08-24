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

cp -r $SYSTEM_ROOT/* $DESTDIR/

cp defaults/modules.load $DESTDIR/etc/modules.load
cp defaults/hostname $DESTDIR/etc/hostname
cp defaults/passwd-livecd $DESTDIR/etc/passwd

if [ -f $DESTDIR/usr/bin/bash ]; then
    # Prefer bash to dash
    sed -i "s/dash/bash/g" $DESTDIR/etc/passwd
fi

cp defaults/fstab $DESTDIR/etc/fstab
cp defaults/shadow $DESTDIR/etc/shadow
cp defaults/profile $DESTDIR/etc/profile
cp defaults/motd $DESTDIR/etc/
cp defaults/autologin $DESTDIR/etc
touch $DESTDIR/etc/livecd
cp defaults/resolv.conf $DESTDIR/etc/resolv.conf

$STRIP -g --strip-unneeded $DESTDIR/usr/lib/*.so
$STRIP -g --strip-all $DESTDIR/usr/bin/*
$STRIP -g --strip-all $DESTDIR/sbin/*
cp $SYSTEM_ROOT/usr/lib/modules/* $DESTDIR/usr/lib/modules
cp -a $SYSTEM_ROOT/usr/lib/ld-onyx* $DESTDIR/usr/lib/

./scripts/install_compiler_slibs.sh $DESTDIR --strip

