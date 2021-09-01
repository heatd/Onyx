# Getting started

So, do you want to try out Onyx? First, you'll need to follow a few steps.

## Step 0: Build Onyx

This is described under doc/building.md.

## Step 1: Creating a sysroot for the disk image

Firstly, we're going to create a system root directory where we're going to store the
operating system and its programs.

First, we're going to create a directory where we're going to store the system root

``` mkdir host_sysroot ```

Then, we will use scripts/create_standard_fs.sh to generate a valid system image onto host_sysroot.

``` scripts/create_standard_fs.sh host_sysroot ```

After that, we can use buildpkg/buildpkg to build packages and use tar to extract them to host_sysroot.

Finally, we're going to create an ext2 partition. You'll need to create a disk image and partition first,
but I assume you already know how to do that (a simple dd + your favourite partitioning software should work).
We'll be assuming the block device is shown at /dev/mapper/loop0p1, like it would if you used kpartx.

``` mkfs.ext2 /dev/mapper/loop0p1 -d host_sysroot ```

We can then delete host_sysroot.

## Step 2: Use your favourite VM or real hardware

If you're looking to use a VM, ```make qemu``` already has a valid command line, for qemu, for the kernel:
it requires an hdd.img present at the project's root that contains the root partition (in ext2 format).

Keep in mind that Onyx requires a 64-bit CPU and crashes and burns if you don't have one.
