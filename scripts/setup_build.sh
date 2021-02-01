#!/bin/sh

if [ "$SYSROOT" = "" ]; then
	SYSROOT=$PWD/sysroot
fi

if [ "$BUILDPKG_BIN" = "" ]; then
	BUILDPKG_BIN=$PWD/buildpkg/buildpkg
fi

export SYSROOT
export BUILDPKG_BIN

cd usystem

gn gen out/

touch --reference=dash/ -c dash/*

cd ..

