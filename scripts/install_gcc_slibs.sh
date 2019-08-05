#!/bin/sh
GCC_PATH=$1
DEST_PATH=$2
LIB_PATH=$GCC_PATH/x86_64-onyx/lib

cp -rv $LIB_PATH/*.so* $DEST_PATH/usr/lib
