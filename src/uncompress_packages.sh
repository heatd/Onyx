#!/bin/sh

for tarball in out/compressed/*.tar*; do
	zstd -d -c -T0 $tarball | tar xvf - -C $DESTDIR
done
