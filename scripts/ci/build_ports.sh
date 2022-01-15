#!/bin/sh
set -e

rm -rf onyx-package-tree
git clone https://github.com/heatd/onyx-package-tree

rm -f *.zst

PACKAGES=""

cd onyx-package-tree

for d in */ ; do
    # GCC can't build with LLVM (see issue #1 of the package tree)
    if [ "$1" = "llvm" ] && [ "$d" = "gcc" ]; then
        true
    else
        PACKAGES="$PACKAGES $d"
    fi
done

cd ..

# TODO: build_sys.py doesn't install packages that aren't dependencies
if ! ./buildpkg/build_sys.py onyx-package-tree . $PACKAGES; then
    echo "Failed to build ports"
    exit 1
fi

for f in *.tar.zst; do
    tar xvf "$f" -C sysroot/
done
