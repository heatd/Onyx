#!/bin/sh
UTILS="cat dmesg echo login ls packmanager true yes printenv uname sleep"
cd utils
for UTIL in $UTILS; do
	echo "Building $UTIL"
	DESTDIR="$PWD/../sysroot" make -j1 -C $UTIL $1 -s
done
cd ..
