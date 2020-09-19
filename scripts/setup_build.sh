#!/bin/sh

if [ "$SYSROOT" = "" ]; then
	SYSROOT=$PWD/sysroot
fi

export SYSROOT

cd usystem

gn gen out/

touch --reference=dash/ -c dash/*

cd ..

