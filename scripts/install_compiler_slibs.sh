#!/bin/sh

TEMP=$(getopt -o "s" --long 'strip,no-c++' -n 'install_compiler_slibs.sh' -- "$@")

eval set -- "$TEMP"

strip_libs=0
no_cxx=0

unset TEMP

while true; do
	case "$1" in
		'-s'|'--strip')
			strip_libs="1"
			shift
			continue
		;;
		'--no-c++')
			no_cxx="1"
			shift
			continue
		;;
		'--')
			shift
			break
		;;
		*)
			break
		;;
	esac
done


DEST_PATH=$1

COMPILER_TYPE="gcc"
TOOLCHAIN_PATH=""

if [ "$CLANG_PATH" != "" ]; then
	TOOLCHAIN_PATH=$CLANG_PATH
	COMPILER_TYPE="clang"
else
	# TODO: We should store the current toolchain's path somewhere, this sucks
	
	# Auto-detect the toolchain path from $HOST-gcc
	TOOLCHAIN_PATH=$(dirname $(which $HOST-gcc))/..
	COMPILER_TYPE="gcc"
fi

if [ "$COMPILER_TYPE" = "gcc" ]; then
	LIB_PATH=$TOOLCHAIN_PATH/$HOST/lib
	LIBSTDCPP_NAME="libstdc++.so*"
else
	target_name="$ONYX_ARCH-unknown-onyx"
	LIB_PATH=$TOOLCHAIN_PATH/lib/$target_name/c++
	LIBSTDCPP_NAME="libc++.so*"
	LIBCXXABI_NAME="libc++abi.so*"
fi

DESTLIB=$DEST_PATH/usr/lib

copy_libs() {
	for lib in $1/*.so*; do
	libname=$(basename $lib)

	# TODO: Match cxxabi.so

	if echo "$libname" | grep -q -e "$LIBSTDCPP_NAME"; then
		is_cxx="1"
	fi

	if [ "$no_cxx" = "1" ] && [ "$is_cxx" = "1" ]; then
		continue
	fi

	cp -v $lib $2
	if [ "$strip_libs" = "1" ]; then
		#$STRIP $2/$libname
		echo
	fi
done
}

copy_libs $LIB_PATH $DESTLIB

if [ "$COMPILER_TYPE" = "clang" ]; then
	# We need to compile the sub-configurations we support
	# Right now, it should only be asan/, noexcept and asan+noexcept, but we do
	# it using a loop for extensibility
	for dir in $LIB_PATH/*/; do
		directory=$(realpath --relative-to=$LIB_PATH $dir)
		mkdir -p $DESTLIB/$directory
		copy_libs $dir $DESTLIB/$directory
	done

fi
