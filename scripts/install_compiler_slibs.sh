#!/bin/sh
set -e
TEMP=$(getopt -o "s" --long 'strip,no-c++' -n 'install_compiler_slibs.sh' -- "$@")

eval set -- "$TEMP"

strip_libs="0"
no_cxx=0

unset TEMP

while true; do
	case "$1" in
		'-s'|'--strip')
			strip_libs="1"
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


DEST_PATH=$1

. scripts/toolchain/detect_toolchain.sh

if [ "$COMPILER_TYPE" = "gcc" ]; then
	LIB_PATH="$TOOLCHAIN_PATH/$HOST/lib/"
	LIBSTDCPP_NAME="libstdc++.so*"
else
	target_name="$ONYX_ARCH-unknown-onyx"
	LIB_PATH="$TOOLCHAIN_PATH/lib/$target_name/"
	CLANG_VERSION=$($TOOLCHAIN_PATH/bin/clang -dumpversion)
	RUNTIME_LIBS="$TOOLCHAIN_PATH/lib/clang/$CLANG_VERSION/lib/$target_name/"
	LIBSTDCPP_NAME="libc++.so*"
	LIBCXXABI_NAME="libc++abi.so*"
fi

DESTLIB=$DEST_PATH/usr/lib

copy_libs() {
	libs=$(find $1 -name "*.so*") 
	for lib in $libs; do
	libname=$(echo "$lib" | grep -oP "^$1\K.*")

	# TODO: Match cxxabi.so

	if echo "$libname" | grep -q -e "$LIBSTDCPP_NAME"; then
		is_cxx="1"
	fi

	if [ "$no_cxx" = "1" ] && [ "$is_cxx" = "1" ]; then
		continue
	fi

	mkdir -p --parents $(dirname $2/$libname)

	cp -av $lib $2/$libname
	if [ "$strip_libs" = "1" ]; then
		$STRIP $2/$libname || true
		echo "Stripped $libname"
	fi
done
}

copy_libs $LIB_PATH $DESTLIB

if [ "$COMPILER_TYPE" = "clang" ]; then
	copy_libs $RUNTIME_LIBS $DESTLIB
fi
