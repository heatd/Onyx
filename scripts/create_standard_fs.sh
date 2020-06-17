#!/bin/sh

MNTROOT=$1

mkdir -p $MNTROOT/usr
mkdir -p $MNTROOT/root
mkdir -p $MNTROOT/dev
mkdir -p $MNTROOT/proc
mkdir -p $MNTROOT/sys
mkdir -p $MNTROOT/home
mkdir -p $MNTROOT/etc
mkdir -p $MNTROOT/usr/lib
mkdir -p $MNTROOT/usr/bin
mkdir -p $MNTROOT/usr/share
mkdir -p $MNTROOT/tmp
mkdir -p $MNTROOT/var
mkdir -p $MNTROOT/sbin

ln -sf usr/lib $MNTROOT/lib
ln -sf usr/bin $MNTROOT/bin

cp defaults/* $MNTROOT/etc

scripts/install_sysroot_to_mnt.sh $MNTROOT
