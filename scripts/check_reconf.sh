#!/bin/sh
set -e

NEEDS_CONFIG=0

if [ "$#" -lt "1" ]; then
	echo "Bad usage: check_reconf.sh [target_package] (optional configure arguments)"
	exit 1
fi

if [ "$ONYX_ARCH" = "" ]; then
	echo "ONYX_ARCH needs to be set!"
	exit 1
fi

if [ "$HOST" = "" ]; then
	echo "HOST needs to be set!"
	exit 1
fi

if [ "$SYSROOT" = "" ]; then
	echo "SYSROOT needs to be set!"
	exit 1
fi

TARGET_PKG=$1

cd $TARGET_PKG

if [ -f "CONF_STAMP" ]; then
	if [ $(cat CONF_STAMP) != "ARCH=${ONYX_ARCH}" ]; then
		NEEDS_CONFIG=1
	fi
else
	NEEDS_CONFIG=1
fi

#echo "Needs conf: ${NEEDS_CONFIG}"

# Shift the arguments by one so we discard the first argument 
shift 1

if [ "$NEEDS_CONFIG" = 0 ]; then
	exit 0
fi

# Try and make clean/make distclean because some makefiles are kind of buggy **cough cough musl**
if [ -f Makefile ]; then
	make distclean || make clean || true
fi

./configure --host=$HOST --with-sysroot=$SYSROOT "$@"

echo "ARCH=${ONYX_ARCH}" > CONF_STAMP
