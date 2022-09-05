#!/bin/sh
set -e

rm -rf onyx-package-tree
git clone https://github.com/heatd/onyx-package-tree

for tarball in *.tar.zst; do
    if [ "$tarball" = "initrd.tar.zst" ]; then
        continue
    fi
    rm -f "$tarball"
done

PACKAGES=""

cd onyx-package-tree

for d in */ ; do
    # Note that we need to trim the trailing slashes
    package=$(echo "$d" | sed 's:/*$::')
    # GCC can't build with LLVM (see issue #1 of the package tree)
    if [ "$1" = "llvm" ] && [ "$package" = "gcc" ]; then
        true
    else
        PACKAGES="$PACKAGES $package"
    fi
done

cd ..

# TODO: build_sys.py doesn't install packages that aren't dependencies
if ! ./buildpkg/build_sys.py onyx-package-tree . $PACKAGES; then
    echo "Failed to build ports"
    exit 1
fi

for f in *.tar.zst; do
    if [ "$f" = "initrd.tar.zst" ]; then
        continue
    fi
    tar xvf "$f" -C sysroot/
done
