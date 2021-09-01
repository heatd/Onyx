# Building guide

This guide documents the Onyx build process. For example usage of this building process, look at `.github/workflows/main.yml`.

Note that steps 0, 1 and 2 can be skipped if you have already done them before.

## Step 0: Set up the build environment

First, you'll need to download the [minimal sysroot](https://storage.googleapis.com/onyx-stuffs/minimal-sysroot.tar.zst).
This allows you to have the toolchain build against a sane libc.
Be sure to export `SYSROOT=$PWD/sysroot` and `ONYX_ARCH=x86_64` (right now, only x86_64 is supported).

## Step 1: Get the toolchains

You can find two scripts, `build_gcc.sh` and `build_llvm.sh`, under `toolchains/scripts`. These build a
GCC and LLVM toolchain for Onyx, respectively. Use these and install the toolchains to a known location.
Note: $GCC_TOOLCHAIN/bin needs to be on the system's $PATH. LLVM has no such requirement.

## Step 2: Set up the kernel config

The kernel build requires a valid `kernel.config` under kernel/. You can look at pre-existing examples
(.example and .minimal) and lay the kernel out yourself; kernel.config.example is a fine choice.

After this point, it's required that SYSROOT, ONYX_ARCH are set and that, if using LLVM, CLANG_PATH points to the
installation path of the LLVM toolchain.

## Step 3: Set up the build

This step only needs to be done once. Run `./scripts/setup_build.sh`.

## Step 4: Build

Do `make -j <nproc> iso` where nproc is the number of threads you want the build to use.

`RUN_CLANG_TIDY=0` might be a useful flag to pass, as it stops the kernel build from running clang-tidy on files.

If everything went well, you will have a Onyx.iso under the base directory!
