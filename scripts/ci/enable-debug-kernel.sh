#!/bin/sh

# TODO: Unclear if we want LTO - it enables more tricky optimizations
# but also makes it hard to debug.

if [ "$ONYX_ARCH" = "x86_64" ]; then
    # Enable UBSAN and KASAN
    sed -i 's/CONFIG_UBSAN=n/CONFIG_UBSAN=y/g' kernel.config
    sed -i 's/CONFIG_KASAN=n/CONFIG_KASAN=y/g' kernel.config
    # Remove ASLR
    sed -i 's/CONFIG_ASLR=y/CONFIG_ASLR=n/g' kernel.config
    sed -i 's/CONFIG_KASLR=y/CONFIG_KASLR=n/g' kernel.config
    # Enable RELOCATABLE_PHYS, since it's a tricky feature
    sed -i 's/CONFIG_RELOCATABLE_PHYS=n/CONFIG_RELOCATABLE_PHYS=y/g' kernel.config
    # Make the kernel UBSAN always abort on error
    echo "CONFIG_UBSAN_ALWAYS_ABORT=y" >> kernel.config
fi
