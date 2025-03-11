#!/bin/sh

. scripts/default-initrd.sh

cp $SYSTEM_ROOT/usr/bin/toybox $DESTDIR/usr/bin
cp $SYSTEM_ROOT/usr/bin/dmesg $DESTDIR/usr/bin

for name in $SYSTEM_ROOT/usr/bin/*; do
    if [ "$(readlink $name)" = "toybox" ]; then
        cp --no-dereference --preserve=links "$name" "$DESTDIR/usr/bin"
    fi
done

./scripts/install_compiler_slibs.sh $DESTDIR --strip
