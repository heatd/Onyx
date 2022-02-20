#!/bin/sh
# Copyright (c) 2021 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#
# SPDX-License-Identifier: MIT
#
set -e
libc_configs="default"

sysroot=$PWD/sysroot
CFLAGS=""

NPROC_UTIL="nproc"

# Add some build quirks for each system 
system=$(uname -s)

case "${system}" in
Darwin*)    NPROC_UTIL="sysctl -n hw.logicalcpu"
            ;;
esac

# If -t 0 or no option was specified, auto-detect the number of threads using the system's number of processors
NR_THREADS=$($NPROC_UTIL)

case "$ONYX_ARCH" in
"riscv64")
    libc_configs="$libc_configs sp"
    ;;
"arm64")
    # Musl uses aarch64
    ONYX_ARCH="aarch64"
    ;;
esac

mkdir -p out/

for config in $libc_configs; do
    dir_name="out/musl-$config"
    rm -rf "$dir_name"
    mkdir -p "$dir_name"

    case "$ONYX_ARCH" in
    "riscv64")
        if [ "$config" = "sp" ]; then
            CFLAGS="$CFLAGS -march=rv64imac -mabi=lp64"
        fi
        ;;
    esac

    cd "$dir_name"
    CFLAGS="$CFLAGS" ../../musl/configure --host="${ONYX_ARCH}-onyx" --with-sysroot="$sysroot" --prefix=/usr --syslibdir=/usr/lib
    DESTDIR="$sysroot" make install -j "$NR_THREADS"

    cd ../..

done
