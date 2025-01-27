#!/bin/sh
set -e

# Note: libzstd-dev was required by GCC builds, in order to leverage zstd compression for LTO, but is now included in
# the base image

sudo apt-get update && sudo apt-get install libmpc-dev libgmp3-dev bison flex libmpfr-dev ninja-build clang lld \
parted mtools meson libfl2 pkgconf qemu-system uuid-dev gettext xorriso generate-ninja
