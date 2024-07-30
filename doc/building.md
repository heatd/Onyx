# Building guide

This guide documents the Onyx build process. For example usage of this building process, look at `.github/workflows/main.yml`.

Note that steps 0, 1 and 2 can be skipped if you have already done them before.

## Step 0: Get required packages

You need the following packages and programs: mtools, xorriso, ninja, gn, grub-mkrescue.
Also you need development files for MPC, MPFR and GMP and texinfo package if you are going to build gcc
and cmake if you are going to build LLVM.

## Step 1: Fetch submodules

Either use `--recursive` flag while cloning the Onyx repository, or issue these commands in repository:

```
git submodule init
git submodule update --recursive
```

## Step 2: Get minimal sysroot (skip if using prebuilt toolchain)

First, you'll need to download the minimal sysroot available in project's github actions artifacts.
This allows you to have the toolchain build against a sane libc.

If you are going to build **gcc**, uncompress sysroot for your arch into the project root.

If you are going to build **LLVM**, you will need sysroots for all supported architectures,
namely x86_64, riscv64 and arm64. Uncompress these sysroots to `sysroots/$arch` directory in
the project root. Additionally, make sysroots/i386 a symlink to x86_64 (`ln -s x86_64 sysroots/i386`
in the project root).

## Step 3: Prepare build environment

1. `export ONYX_ARCH=x86_64`
2. Run `make -C kernel defconfig` or obtain a .config through other means. The `menuconfig`
target can be used to change a config graphically, and you can also use `oldconfig` to update
an older config file.

## Step 4: Build or obtain the toolchains

### Obtaining prebuilt toolchains

These are available for Linux and macOS in the project's github action artifacts,
under `build-toolchain-${os}` or `build-toolchain-llvm-${os}`. Note that macOS LLVM builds are broken.

### Building toolchains

`toolchains/scripts/build_toolchain.sh` will do it for you. You need to choose staging and target
directory toolchain. Target toolchain directory further will be referred as `$TOOLCHAIN_TARGET_DIR`.

### Adding toolchain paths to environment

If using **gcc**: add `$TOOLCHAIN_TARGET_DIR/bin` to `$PATH`.

If using **LLVM**: `export CLANG_PATH=$TOOLCHAIN_TARGET_DIR`.

## Step 5: Build

First, run `scripts/setup_build.sh`

Then do `make -j <nproc> liveiso` where nproc is the number of threads you want the build to use.

If everything went well, you will have a Onyx.iso under the base directory!
