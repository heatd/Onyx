# Building an Onyx toolchain

This file will describe the procedure required to build an onyx toolchain. Note that SYSROOT and PREFIX need to be defined with the path to the Onyx source tree's sysroot ($ONYX_ROOT/sysroot) and the destination for the toolchain, respectively.

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
../gcc-9.1.0/configure --target=x86_64-onyx --prefix=$PREFIX --with-sysroot=$SYSROOT --enable-languages=c,c++ --disable-nls --enable-threads=posix --enable-libstdcxx-threads --enable-symvers=gnu
make all-target all-target-libgcc all-target-libstdc++-v3 -j4
make install-target install-target-libgcc install-target-libstdc++-v3 -j4
```

## Conclusion

Everything should be done by now, just add $PREFIX/bin to your $PATH and you should be set!
