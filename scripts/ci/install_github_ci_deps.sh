#!/bin/sh
set -e
system=$(uname -s)

case "${system}" in
Darwin*)    scripts/ci/install_macos_deps.sh
            ;;
Linux*)     scripts/ci/install_ubuntu_deps.sh
            ;;
esac
