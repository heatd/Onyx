
if [ -z "$CLANG_PATH" ]; then
	echo "Error: CLANG_PATH must be set!"
fi

if [ -z "$SYSROOT" ]; then
	echo "Error: SYSROOT must be set!"
fi

if [ "$USE_GCC" = 1 ]; then
	export CC=x86_64-onyx-gcc
	export CXX=x86_64-onyx-g++
	export LD=x86_64-onyx-ld
else

export CC=${CLANG_PATH}/bin/clang
export CXX=${CLANG_PATH}/bin/clang++
export AR=${CLANG_PATH}/bin/llvm-ar
export STRIP=${CLANG_PATH}/bin/llvm-strip
export READELF=${CLANG_PATH}/bin/llvm-readelf
export LD=${CLANG_PATH}/bin/clang
export CXXFLAGS="--target=x86_64-unknown-onyx --sysroot=${SYSROOT}"
export CFLAGS="--target=x86_64-unknown-onyx --sysroot=${SYSROOT}"
export LDFLAGS="--target=x86_64-unknown-onyx --sysroot=${SYSROOT}"

fi
