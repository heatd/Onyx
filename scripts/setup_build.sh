#!/bin/sh

if [ "$SYSROOT" = "" ]; then
	SYSROOT=$PWD/sysroot
fi

cd usystem

gn gen out/

cd dash
./configure --prefix=/ --bindir=/usr/bin --host=x86_64-onyx --enable-static
cd ..

cd ..

