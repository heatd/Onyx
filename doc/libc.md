#The kernel's libc

## Overview
The Spartix kernel uses a very small kernel-exclusive libc. It contains the bare minimum that it needs to perform its function. That means no fancy functions, C11 threads, extensive libm, POSIX, etc.
## Functions Available in libc
The only functions that should be available in the Spartix's libc are not a lot. The whole C Standard Library should NOT be ported. The only functions that should be implemented are functions that might be useful to kernel programing.
## The Principle
It's principle is that it should be light-weight AND functional. This will not turn into a glibc of a mess.
## Warnings
Don't try to link it with a user-space program. You should use newlib instead (or a port of glibc if i ever try one, if it ever stops to be bloated)
