if [ -z "$SYSROOT" ]; then
	echo "Error: SYSROOT must be set!"
fi

export HOST=$ONYX_TARGET

if [ "$ONYX_DONT_FORCE_CC_ENV" != "true" ]; then

	if [ -z "$CLANG_PATH" ]; then
		export CC="$HOST-gcc"
		export CXX="$HOST-g++"
		export LD="$HOST-ld"
		export CFLAGS="--sysroot=$SYSROOT"
		export CXXFLAGS=$CFLAGS
		export CPPFLAGS=$CFLAGS
		export LDFLAGS=$CFLAGS
		export STRIP=$HOST-strip
		export ONYX_CROSS_COMPILE_PREFIX=$HOST-
	else

	export ONYX_CLANG_ARGS="--target=$ONYX_ARCH-unknown-onyx --sysroot=$SYSROOT"
	export CC="${CLANG_PATH}/bin/clang"
	export CXX="${CLANG_PATH}/bin/clang++"
	export AR="${CLANG_PATH}/bin/llvm-ar"
	export STRIP="${CLANG_PATH}/bin/llvm-strip"
	export READELF="${CLANG_PATH}/bin/llvm-readelf"
	export LD="${CLANG_PATH}/bin/ld.lld"
	export OBJDUMP="${CLANG_PATH}/bin/llvm-objdump"
	export RANLIB="${CLANG_PATH}/bin/llvm-ranlib"
	export ONYX_USING_LLVM="yes"
	export CFLAGS="$ONYX_CLANG_ARGS"
	export CPPFLAGS="$ONYX_CLANG_ARGS"
	export CXXFLAGS="$ONYX_CLANG_ARGS"
	export LDFLAGS="$ONYX_CLANG_ARGS"
	export ONYX_CROSS_COMPILE_PREFIX="${CLANG_PATH}/bin/"

	fi
fi

export PKG_CONFIG=$SYSROOT/../buildpkg/onyx-pkg-config
export PKG_CONFIG_FOR_BUILD=pkg-config
