#!/bin/sh

if [ "$SYSROOT" = "" ]; then
	SYSROOT=$PWD/sysroot
fi

if [ "$BUILDPKG_BIN" = "" ]; then
	BUILDPKG_BIN=$PWD/buildpkg/buildpkg
fi

if [ "$BUILDPKG_BIN_PY_WRAPPER" = "" ]; then
	BUILDPKG_BIN_PY_WRAPPER=$PWD/buildpkg/buildpkg_gn_wrapper
fi

export SYSROOT
export BUILDPKG_BIN
export BUILDPKG_BIN_PY_WRAPPER

cd usystem

gn gen out/

touch --reference=dash/ -c dash/*

cd ..

