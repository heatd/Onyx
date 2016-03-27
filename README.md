# Spartix
## An x86/x86_64 Operating system
Spartix is a Unix-like operating system, designed to run on x86 and x86_64. It's designed to comply to the POSIX standard, implement all the standard Unix API's, while learning from the mistakes UNIX did.
It folows the System V ABI. All the system calls are exposed under the interrupt vector 0x80, like Linux.
Spartix's purpose is to be function-heavy, and light-weight when possible. Bloat is a NOT a necessary evil for functionality, as software can be very functional, while remaining light-weight (something like GIMP comes to my mind, compared to Adobe Photoshop). Spartix will never turn into a glibc or a systemd, as those pieces of software add unnecessary crap to its binary. Spartix doesn't try to fight and say that it is "very light-weight" or "super-quick". It affirms that it is an Operating System that won't implement, for example GUI's, because then the kernel would be "more than 20 KiB". 
## In order to build Spartix, you need:

- An i686-elf cross compiler (Instructions can be found at __http://wiki.osdev.org/GCC_Cross_Compiler__ )
- Grub 2 installed on your machine (Doesn't matter if you boot your system using Grub 2, you just need the utilities)
- POSIX shell ( Bash is the most common, but things like Cygwin and MSYS will work too)
- Unix like environment
