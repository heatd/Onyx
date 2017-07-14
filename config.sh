#!/bin/sh
SYSTEM_HEADER_PROJECTS="libc libdrm kernel"
PROJECTS="libc libdrm kernel"
SOURCE_PACKAGES="musl libunwind init games ld"

export MAKE=${MAKE:-make}
export HOST=${HOST:-$(./default-host.sh)}

export AR=${HOST}-ar
export AS=${HOST}-as
export CC=${HOST}-gcc
export CXX=${HOST}-g++
export NM=${HOST}-nm
export HOST_CC=gcc
export PREFIX=/usr
export EXEC_PREFIX=$PREFIX
export BOOTDIR=/boot
export LIBDIR=$EXEC_PREFIX/lib
export INCLUDEDIR=$PREFIX/include
export BINDIR=$PREFIX/bin
export MANDIR=/usr/share/man
export PKGDIR=/pkg
export CFLAGS='-Os -g -Werror'
export CPPFLAGS=''

# Configure the cross-compiler to use the desired system root.
export CXX="$CXX --sysroot=$PWD/sysroot"
export CC="$CC --sysroot=$PWD/sysroot"
