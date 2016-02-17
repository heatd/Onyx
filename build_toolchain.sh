#!/bin/bash
DESTDIR=$1
#Define this variable to your preference,this is default
MAKEOPTS="-j4"
NEWLIB=newlib-2.3.0.20160104
CURRDIR=$(pwd)
#Check if the needed commands exist
command -v wget >/dev/null 2>&1 || { echo >&2 "This script requires wget but it's not installed.  Aborting."; exit 1; }
command -v tar >/dev/null 2>&1 || { echo >&2 "This script requires tar but it's not installed.  Aborting."; exit 1; }
command -v patch >/dev/null 2>&1 || { echo >&2 "This script requires patch but it's not installed.  Aborting."; exit 1; }
if (( $DESTDIR = 0 ))
	DESTDIR="$CURRDIR/i686-spartanos";

[[ ! -d $NEWLIB ]] && wget ftp://sourceware.org/pub/newlib/newlib-2.3.0.20160104.tar.gz && tar -xvf newlib-2.3.0.20160104.tar.gz
echo "Patching $NEWLIB"
patch -p0 < "$NEWLIB-spartix.patch"
mkdir -p newlib-build
echo "Building newlib"
cd newlib-build
../$NEWLIB/configure --target=i686-spartix --prefix=/usr
make $MAKEOPTS
make DESTDIR=../sysroot/ install $MAKEOPTS
make clean
cd .. && rm -rf newlib-build
echo "Newlib built"