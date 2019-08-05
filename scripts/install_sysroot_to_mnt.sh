#!/bin/sh
sudo cp -rTv sysroot/ /mnt

toolchain=$(dirname `which x86_64-onyx-gcc`)/..

sudo ./scripts/install_gcc_slibs.sh $toolchain /mnt
