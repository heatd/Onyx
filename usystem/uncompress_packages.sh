#!/bin/sh

if [ ! -d out/compressed ]; then
	exit
fi

for tarball in out/compressed/*.tar*; do
	zstd -d -c -T0 $tarball | tar xvf - -C $DESTDIR
done
