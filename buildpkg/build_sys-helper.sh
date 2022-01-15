#!/bin/sh
set -e
. ${ONYX_ROOT}/scripts/setup_package_build_env.sh

exec ${ONYX_ROOT}/buildpkg/buildpkg $1 build+package
