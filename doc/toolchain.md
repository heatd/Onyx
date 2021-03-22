# Building an Onyx toolchain

This file will describe the procedure required to build an onyx toolchain. Note that SYSROOT and PREFIX need to be defined with the path to the Onyx source tree's sysroot ($ONYX_ROOT/sysroot) and the destination for the toolchain, respectively. The SYSROOT needs to have at *least* a minimal sysroot.

## Building Binutils

To build binutils you need `binutils-2.32.patch` and a copy of the original `binutils 2.32` that you can find at gcc.gnu.org.

With the patch you want to

```bash
cd binutils-2.32
patch -p1 < ../binutils-2.32.patch
cd ..
mkdir binutils-2.32-build
cd binutils-2.32-build
../binutils-2.32/configure --target=x86_64-onyx --prefix=$PREFIX --with-sysroot=$SYSROOT --disable-werror --disable-nls --enable-gold=default --enable-lto --enable-plugins
make all -j8
make install -j8
```

## Building GCC

Again, get `gcc-9.1.0.patch` and a copy of the original `gcc 9.1.0` at gcc.gnu.org.

Then, do:

```bash
cd gcc-9.1.0
patch -p1 < ../gcc-9.1.0.patch
cd ..
mkdir gcc-9.1.0-build
cd gcc-9.1.0-build
../gcc-9.1.0/configure --target=x86_64-onyx --prefix=$PREFIX --with-sysroot=$SYSROOT --enable-languages=c,c++ --disable-nls --enable-threads=posix --enable-libstdcxx-threads --enable-symvers=gnu --enable-default-pie --enable-lto --enable-default-ssp --enable-shared
make all-target all-target-libgcc all-target-libstdc++-v3 -j4
make install-target install-target-libgcc install-target-libstdc++-v3 -j4
```

## Conclusion

Everything should be done by now, just add $PREFIX/bin to your $PATH and you should be set!

## Addendum

## Building binutils to run on Onyx itself

Using /mnt as the place where the partition is mounted:

Notes:

- Don't default to gold because mmap MAP_SHARED and dirtying the filesystem doesn't work yet (kernel issue) and there may be other issues besides that one

```bash
../binutils-2.32/configure --host=x86_64-onyx --prefix=/usr --with-sysroot= --with-build-sysroot=/mnt --disable-werror --disable-nls --enable-gold --enable-lto --enable-plugins
```

## LLVM toolchain

First, download and patch it using toolchains/download_patch_llvm.sh.

Then, use the following command:

```bash
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_LINK_LLVM_DYLIB=ON -DCLANG_LINK_CLANG_DYLIB=ON -DLLVM_ENABLE_RTTI=ON -DLLVM_ENABLE_LTO=OFF -DLINUX_x86_64-unknown-linux-gnu_SYSROOT=/ -DONYX_SRCDIR=$ONYX_SRCDIR
-DCMAKE_INSTALL_PREFIX= -C ${LLVM_SRCDIR}/clang/cmake/caches/Onyx-stage2.cmake ${LLVM_SRCDIR}/llvm

ninja distribution
DESTDIR=$TOOLCHAIN_DEST ninja install
```

where ONYX_SRCDIR should be your Onyx base directory, LLVM_SRCDIR should be the base directory of the llvm repo
you just downloaded and patched and TOOLCHAIN_DEST should be the destination directory.
