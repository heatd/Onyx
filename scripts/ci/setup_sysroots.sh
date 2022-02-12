#!/bin/bash
mkdir -p sysroots

if [ "$1" = "llvm" ]; then

for sysroot in minimal-sysroot-*/; do
    arch=$(echo $sysroot | grep -Po '(?<=minimal-sysroot-)[^/]*')
    sysroot=${sysroot%/}
    mkdir -p sysroots/$arch
    zstd -d "$sysroot/${sysroot}.tar.zst" --stdout | tar x -C sysroots/$arch
done

ln -s x86_64 sysroots/i386

else
    zstd -d minimal-sysroot-$2/minimal-sysroot-$2.tar.zst --stdout | tar x
fi
