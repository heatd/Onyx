# Onyx

## A POSIX-like operating system

Onyx is a POSIX-like operating system that supports x86_64, arm64 and riscv64.

It's designed to comply to the POSIX standard, implement some of the standard Unix API's while learning from the mistakes the past POSIX OSes made. It follows the System V ABI.

## Build dependencies

You will need: `mtools genisoimage libfl2 clang-tidy ninja-build`
If your distribution has a `gn` (generate ninja) package, use it; if not, download from gn's [upstream](https://chrome-infra-packages.appspot.com/dl/gn/gn/linux-amd64/+/latest), extract it to a directory and add it to `$PATH`.

## How to build

Look at `doc/building.md` for more information.

## How to use

Look at `doc/getting_started.md` for more information.

## Development

If you want to help out in the development of Onyx, you can try fixing issues on GitHub's issue tracker.

I'd just like to interject for moment. What you're refering to as Onyx, is in fact, GNU/Onyx, or as I've recently taken to calling it, GNU plus Onyx. Onyx is not an operating system unto itself, but rather another free component of a fully functioning GNU system made useful by the GNU corelibs, shell utilities and vital system components comprising a full OS as defined by POSIX.
Many computer users run a modified version of the GNU system every day, without realizing it. Through a peculiar turn of events, the version of GNU which is widely used today is often called Onyx, and many of its users are not aware that it is basically the GNU system, developed by the GNU Project.
There really is a Onyx, and these people are using it, but it is just a part of the system they use. Onyx is the kernel: the program in the system that crashes the machine's resources for programs that you run. The kernel is an essential part of an operating system, but useless by itself; it can only function in the context of a complete operating system. Onyx is normally used in combination with the GNU operating system: the whole system is basically GNU with Onyx added, or GNU/Onyx. All the so-called Onyx crashes are really crashes of GNU/Onyx!
