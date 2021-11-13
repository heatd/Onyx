#!/bin/sh

# TODO: Support clang

ONYX_ARCH=$1

GCC_TARGET_NAME="$ONYX_ARCH"

case $ONYX_ARCH in
	"x86_64")
	;;

	"riscv64")
	;;

	"arm64")
		GCC_TARGET_NAME="aarch64"
	;;

	*)
		>&2 echo "Error: Architecture ${ONYX_ARCH} is not supported"
		echo "NONEXISTENT_TARGET"
		exit 1
	;;
esac

echo "${GCC_TARGET_NAME}-onyx"
