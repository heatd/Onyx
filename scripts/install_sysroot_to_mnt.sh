#!/bin/sh

MNTROOT=$1

if [ "$MNTROOT" = "" ]; then
	MNTROOT=/mnt
fi

export ONYX_ARCH=$(./scripts/onyx_arch.sh)
export HOST=$(./scripts/arch-to-host.sh $ONYX_ARCH)
export STRIP=$CLANG_PATH/bin/llvm-strip

mkdir -p temp_sysroot

cp -rTv sysroot/ $PWD/temp_sysroot

./scripts/install_compiler_slibs.sh $PWD/temp_sysroot

cp -rTv $PWD/temp_sysroot $MNTROOT

rm -rf temp_sysroot
