#!/bin/sh
set -e

sudo apt-get update && sudo apt-get install libmpc-dev libgmp3-dev bison flex libmpfr-dev zstd ninja-build clang lld
mkdir gn_bin/
cd gn_bin
wget -q https://chrome-infra-packages.appspot.com/dl/gn/gn/linux-amd64/+/latest -O gn.zip
unzip gn.zip
