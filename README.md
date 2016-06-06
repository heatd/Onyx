#Spartix
## An x86_64 Operating system
Spartix is an operating system,
    designed to run on x86_64.
    It
    's designed to comply to the POSIX standard, implement some of the standard Unix API'
    s,
    while learning from the mistakes UNIX did.It folows the System V ABI.
    All the system calls are exposed through syscall.Spartix
    's purpose is to be function-heavy, and light-weight when possible. Bloat is a NOT a necessary evil for functionality, as software can be very functional, while remaining light-weight (something like GIMP comes to my mind, compared to Adobe Photoshop). Spartix will never turn into a glibc or a systemd, as those pieces of software add unnecessary crap to its binary. Spartix doesn'
    t try to fight and say that it is "very light-weight" or "super-quick".
    It affirms that it is not an Operating System that won
    't implement, for example GUI' s,
    because then the kernel would be "more than 20 KiB".
