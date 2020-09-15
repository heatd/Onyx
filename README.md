# Onyx

## An x86_64 Operating system

Onyx is an operating system, designed to run on x86_64.

It's designed to comply to the POSIX standard, implement some of the standard Unix API's while learning from the mistakes UNIX did. It follows the System V ABI.

All the system calls are exposed through syscall.

Onyx's purpose is to be function-heavy, and light-weight when possible. Bloat is *NOT* a necessary evil for functionality, as software can be very functional, while remaining light-weight. Onyx will never turn into a glibc or a systemd, as those pieces of software add unnecessary crap to its binary.

## Build dependencies

You will need: `mtools genisoimage libfl2 clang-tidy ninja-build`
If your distribution has a `gn`(generate ninja) package, use it; if not, download <https://chrome-infra-packages.appspot.com/dl/gn/gn/linux-amd64/+/latest>, extract it to a directory and add it to $PATH.

## How to build

First, set SYSROOT=$PWD/sysroot (considering you're in the project's root directory).

Then, you need to do scripts/setup_build.sh; after that, you should be good to go, considering you already have an Onyx toolchain set up(if not, go to <https://github.com/heatd/onyx-toolchains> and make sure the toolchain's `bin/`
is in $PATH);

## Development

If you want to help out in the development of Onyx, you can try joining #onyx-os on freenode, or fixing issues on GitHub's issue tracker.

I'd just like to interject for moment. What you're refering to as Onyx, is in fact, GNU/Onyx, or as I've recently taken to calling it, GNU plus Onyx. Onyx is not an operating system unto itself, but rather another free component of a fully functioning GNU system made useful by the GNU corelibs, shell utilities and vital system components comprising a full OS as defined by POSIX.
Many computer users run a modified version of the GNU system every day, without realizing it. Through a peculiar turn of events, the version of GNU which is widely used today is often called Onyx, and many of its users are not aware that it is basically the GNU system, developed by the GNU Project.
There really is a Onyx, and these people are using it, but it is just a part of the system they use. Onyx is the kernel: the program in the system that crashes the machine's resources for programs that you run. The kernel is an essential part of an operating system, but useless by itself; it can only function in the context of a complete operating system. Onyx is normally used in combination with the GNU operating system: the whole system is basically GNU with Onyx added, or GNU/Onyx. All the so-called Onyx crashes are really crashes of GNU/Onyx!
