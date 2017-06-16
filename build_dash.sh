#!/bin/sh
cd dash
export CFLAGS="-O2 -Wno-error"
./configure --prefix=/ --bindir=/usr/bin --host=x86_64-onyx --enable-static
make all -j3
make install
make clean
make distclean
cd ..
# After installing dash, install an /etc/profile
cp profile sysroot/etc/profile
