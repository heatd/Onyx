#!/bin/sh
UTILS="cat dmesg echo login ls packmanager true yes printenv"
cd utils
for UTIL in $UTILS; do
	echo "Building $UTIL"
	DESTDIR="$PWD/../sysroot" $MAKE -C $UTIL $1 -s
done
cd ..
