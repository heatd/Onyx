#!/bin/sh
UTILS="cat dmesg echo login ls packmanager true yes printenv uname sleep memstat link rm mkdir"
cd utils
for UTIL in $UTILS; do
	echo "Building $UTIL"
	DESTDIR="$PWD/../sysroot" make -C $UTIL $1 -s
done
cd ..
