SYSTEM_HEADER_PROJECTS="libc libdrm kernel"
PROJECTS="libc libdrm kernel"
SOURCE_PACKAGES="musl cat echo init login sh lua"

export MAKE=${MAKE:-make}
export HOST=${HOST:-$(./default-host.sh)}

export AR=${HOST}-ar
export AS=${HOST}-as
export CC=${HOST}-gcc
export CXX=${HOST}-g++
export PREFIX=/usr
export EXEC_PREFIX=$PREFIX
export BOOTDIR=/boot
export LIBDIR=$EXEC_PREFIX/lib
export INCLUDEDIR=$PREFIX/include
export PKGDIR=/pkg
export CFLAGS='-Os -g -Wno-format -Werror -mno-red-zone'
export CPPFLAGS=''

# Configure the cross-compiler to use the desired system root.
export CXX="$CXX --sysroot=$PWD/sysroot"
export CC="$CC --sysroot=$PWD/sysroot"

# Work around that the -elf gcc targets doesn't have a system include directory
# because configure received --without-headers rather than --with-sysroot.
if echo "$HOST" | grep -Eq -- '-elf($|-)'; then
    export CXX="$CXX -isystem=$INCLUDEDIR"
    export CC="$CC -isystem=$INCLUDEDIR"
fi
