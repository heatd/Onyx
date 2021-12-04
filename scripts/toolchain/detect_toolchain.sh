COMPILER_TYPE="gcc"
TOOLCHAIN_PATH=""

if [ "$CLANG_PATH" != "" ]; then
	TOOLCHAIN_PATH=$CLANG_PATH
	COMPILER_TYPE="clang"
	STRIP=$CLANG_PATH/bin/llvm-strip
else
	# TODO: We should store the current toolchain's path somewhere, this sucks
	
	# Auto-detect the toolchain path from $HOST-gcc
	TOOLCHAIN_PATH=$(dirname $(which $HOST-gcc))/..
	COMPILER_TYPE="gcc"
	STRIP=$HOST-strip
fi
