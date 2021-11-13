#!/bin/sh

if [ "$ONYX_ARCH" = "" ]; then
	ONYX_ARCH=$(uname -m)

	# We need to convert from linux uname -m values to Onyx architectures
	case $ONYX_ARCH in
		"aarch64")
			ONYX_ARCH="arm64"
		;;
	esac
fi

echo $ONYX_ARCH
