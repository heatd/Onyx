#!/bin/sh
set -e
brew install zstd gmp mpfr libmpc wget unzip make ninja coreutils gnu-getopt texinfo
mkdir gn_bin/
cd gn_bin
wget -q https://chrome-infra-packages.appspot.com/dl/gn/gn/mac-amd64/+/latest -O gn.zip
unzip gn.zip
cd ..
