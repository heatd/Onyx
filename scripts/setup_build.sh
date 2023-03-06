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

GN_ARGS="target_cpu = \"$ONYX_ARCH\"\ntarget_os=\"onyx\"\n"

if [ "$CLANG_PATH" != "" ]; then
	GN_ARGS="$GN_ARGS clang_path = \"$CLANG_PATH\"\n"
fi

cd usystem

if [ "$GN_ARGS" != "" ] && [ -f out/args.gn ]; then
	printf "$GN_ARGS" > out/args.gn
	done_stuff="1"
fi

gn gen out/ --export-compile-commands

if [ "$GN_ARGS" != "" ] && [ "$done_stuff" != "1" ]; then
	printf "$GN_ARGS" > out/args.gn

	gn gen out/ --export-compile-commands
fi

touch -r dash/ -c dash/*

cd ..

