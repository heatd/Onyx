#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -e

if [ "$#" -ne "1" ]; then
	echo "rename-nlink-tests.sh: Bad usage" 1>&2
    echo "rename-nlink-tests [test dir]" 1>&2
	exit 1
fi

dir=$1

if [ "$dir" = "" ]; then
    exit 1
fi

mkdir -p "$dir"
rm -rf "$dir"/*

# Test 1: Create files and assert that the nlink makes sense
touch "$dir"/a "$dir"/b
nlink=$(stat -c '%h' "$dir")

if [ $nlink != 2 ]; then
    echo "Bad nlink $nlink" 1>&2
    exit 2
fi

# Create a dir and assert it again
mkdir "$dir"/d0
nlink=$(stat -c '%h' "$dir")

if [ $nlink != 3 ]; then
    echo "Bad nlink $nlink" 1>&2
    exit 3
fi

echo "[PASSED] test 1: original nlink ok"

# Test 2: Rename the dir around and assert that we don't screw up the nlink
mv "$dir"/d0 "$dir"/d1
nlink=$(stat -c '%h' "$dir")

if [ $nlink != 3 ]; then
    echo "Bad nlink $nlink" 1>&2
    exit 4
fi

mv "$dir"/d1 "$dir"/d0

nlink=$(stat -c '%h' "$dir")

if [ $nlink != 3 ]; then
    echo "Bad nlink $nlink" 1>&2
    exit 5
fi

echo "[PASSED] test 2: dir renames ok"

# Test 3: Rename a dir in/out and assert that nlinks change correctly

mkdir "$dir"/d1

nlink=$(stat -c '%h' "$dir")

if [ $nlink != 4 ]; then
    echo "Bad nlink $nlink" 1>&2
    exit 6
fi

nlink=$(stat -c '%h' "$dir"/d0)

if [ $nlink != 2 ]; then
    echo "Bad nlink $nlink" 1>&2
    exit 7
fi

mv "$dir"/d1 "$dir/d0"

nlink=$(stat -c '%h' "$dir")

if [ $nlink != 3 ]; then
    echo "Bad nlink $nlink" 1>&2
    exit 8
fi

nlink=$(stat -c '%h' "$dir"/d0)

if [ $nlink != 3 ]; then
    echo "Bad nlink $nlink" 1>&2
    exit 9
fi

mv "$dir"/d0/d1 "$dir"

nlink=$(stat -c '%h' "$dir")

if [ $nlink != 4 ]; then
    echo "Bad nlink $nlink" 1>&2
    exit 10
fi

nlink=$(stat -c '%h' "$dir"/d0)

if [ $nlink != 2 ]; then
    echo "Bad nlink $nlink" 1>&2
    exit 11
fi

echo "[PASSED] test 3: dir rename in/out ok"
