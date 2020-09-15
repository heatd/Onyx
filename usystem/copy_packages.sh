#!/bin/sh

for dir in out/packages/*/; do
	cp -r $dir* $DESTDIR/
done
