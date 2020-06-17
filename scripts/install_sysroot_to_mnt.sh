#!/bin/sh

MNTROOT=$1

if [ "$MNTROOT" == "" ]; then
	MNTROOT=/mnt
fi

sudo cp -rTv sysroot/ $MNTROOT

toolchain=$(dirname `which x86_64-onyx-gcc`)/..

sudo ./scripts/install_gcc_slibs.sh $toolchain $MNTROOT
