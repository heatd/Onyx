#!/bin/sh

if [ "$SYSROOT" = "" ]; then
	SYSROOT=$PWD/sysroot
fi

export SYSROOT

cd usystem

gn gen out/

cd ..

