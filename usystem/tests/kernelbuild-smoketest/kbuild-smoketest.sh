#!/bin/sh
set -e
cp -r /kernel /tmp
cp -r /scripts /tmp

cd /tmp/kernel

while true; do

export CC=gcc CXX=g++ AR=ar NM=nm STRIP=strip
make vmonyx -j8
make clean -j4

done
