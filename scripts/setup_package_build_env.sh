if [ -z "$SYSROOT" ]; then
	echo "Error: SYSROOT must be set!"
fi

export HOST=$ONYX_TARGET

if [ -z "$CLANG_PATH" ]; then
	export CC="$HOST-gcc --sysroot=$SYSROOT"
	export CXX="$HOST-g++ --sysroot=$SYSROOT"
	export LD="$HOST-ld --sysroot=$SYSROOT"
	export STRIP=$HOST-strip
	export ONYX_CROSS_COMPILE_PREFIX=$HOST-
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
export ONYX_USING_LLVM="yes"
export ONYX_CROSS_COMPILE_PREFIX="${CLANG_PATH}/bin/"

fi
