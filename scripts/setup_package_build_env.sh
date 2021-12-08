if [ -z "$SYSROOT" ]; then
	echo "Error: SYSROOT must be set!"
fi

export HOST=$ONYX_ARCH-onyx

if [ -z "$CLANG_PATH" ]; then
	export CC=$HOST-gcc
	export CXX=$HOST-g++
	export LD=$HOST-ld
	export STRIP=$HOST-strip
else

export ONYX_CLANG_ARGS="--target=$ONYX_ARCH-unknown-onyx --sysroot=$SYSROOT"
export CC="${CLANG_PATH}/bin/clang $ONYX_CLANG_ARGS"
export CXX="${CLANG_PATH}/bin/clang++ $ONYX_CLANG_ARGS"
export AR="${CLANG_PATH}/bin/llvm-ar"
export STRIP="${CLANG_PATH}/bin/llvm-strip"
export READELF="${CLANG_PATH}/bin/llvm-readelf"
export LD="${CLANG_PATH}/bin/ld.lld --sysroot=$SYSROOT"
export OBJDUMP="${CLANG_PATH}/bin/llvm-objdump"
export RANLIB="${CLANG_PATH}/bin/llvm-ranlib"

fi
