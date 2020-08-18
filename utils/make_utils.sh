#!/bin/sh
UTILS="dmesg login packmanager memstat ping"
cd utils
for UTIL in $UTILS; do
	echo "Building $UTIL"
	DESTDIR="$PWD/../sysroot" make -C $UTIL $1 -s
done
cd ..
