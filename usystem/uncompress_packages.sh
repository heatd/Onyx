#!/bin/sh

for tarball in out/compressed/*.tar*; do
	tar xvf $tarball -C $DESTDIR
done
