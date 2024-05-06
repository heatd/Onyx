#!/bin/sh
set -e

TEMP=$(getopt -o "" --long 'no-strip,no-c++' -n 'create_standard_fs.sh' -- "$@")

eval set -- "$TEMP"

strip_bins="1"
no_cxx=0

unset TEMP

while true; do
	case "$1" in
		'--no-strip')
			strip_bins="0"
			shift
		;;
		'--no-c++')
			no_cxx="1"
			shift
		;;
		'--')
			shift
			break
		;;
	esac
done


export ONYX_ARCH=$(./scripts/onyx_arch.sh)
export HOST=$(./scripts/arch-to-host.sh $ONYX_ARCH)

. scripts/toolchain/detect_toolchain.sh

MNTROOT=$1

if [ -d "$MNTROOT" ]; then
    rm -rf "$MNTROOT"
fi

mkdir -p $MNTROOT/usr
mkdir -p $MNTROOT/root
mkdir -p $MNTROOT/dev
mkdir -p $MNTROOT/proc
mkdir -p $MNTROOT/sys
mkdir -p $MNTROOT/home
mkdir -p $MNTROOT/etc
mkdir -p $MNTROOT/usr/lib
mkdir -p $MNTROOT/usr/bin
mkdir -p $MNTROOT/usr/share
mkdir -p $MNTROOT/tmp
mkdir -p $MNTROOT/var
mkdir -p $MNTROOT/sbin

ln -sf usr/lib $MNTROOT/lib
ln -sf usr/bin $MNTROOT/bin

cp defaults/* $MNTROOT/etc

cp -r sysroot/* "$MNTROOT"

COMPILER_SLIBS_ARGS=

if [ "$strip_bins" = "1" ]; then
    COMPILER_SLIBS_ARGS="$COMPILER_SLIBS_ARGS --strip"
fi

if [ "$no_cxx" = "1" ]; then
    COMPILER_SLIBS_ARGS="$COMPILER_SLIBS_ARGS --no-cxx"
fi

./scripts/install_compiler_slibs.sh "$MNTROOT" "$COMPILER_SLIBS_ARGS"

if [ "$strip_bins" = "1" ]; then
    dirs="usr/bin sbin usr/lib"

    for dir in $dirs; do
        find "$MNTROOT/$dir" -type f -exec sh -c '(! echo {} | grep -q .*[.]o) && (! echo {} | grep -q .*grub.*) && (file {} | grep ELF)' \; -exec "$STRIP" {} \; || true
    done
fi
