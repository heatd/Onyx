#!/bin/sh

# TODO: Support clang

if [ "$ONYX_ARCH" = "" ]; then
	ONYX_ARCH=$(uname -m)

	# We need to convert from linux uname -m values to Onyx architectures
	case $ONYX_ARCH in
		"aarch64")
			ONYX_ARCH = "arm64"
			break
		;;
fi

GCC_TARGET_NAME=$ONYX_ARCH

case $ONYX_ARCH in
	"x86_64")
		break
	;;

	"arm64")
		GCC_TARGET_NAME = "aarch64"
		break
	;;

	*)
		>&2 echo "Error: Architecture ${ONYX_ARCH} is not supported"
		echo "NONEXISTENT_TARGET"
		exit 1
	;;
esac

echo ${GCC_TARGET_NAME}-onyx
