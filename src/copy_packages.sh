#!/bin/sh

set -e

for dir in out/packages/*/; do
	cp -r $dir* $DESTDIR/
done

cp -r out/obj/sysroot-$ONYX_ARCH/* $DESTDIR/

#find out/obj -name "manifest.json" -exec sh -c '../scripts/build/copy_package.py $(dirname {}) $DESTDIR' \;
