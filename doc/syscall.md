# System Calls

The kernel exposes the system calls to the user-space by the interrupt vector 0x80 ( 128 decimal ). In the future, syscall will be supported.

## Table of System calls

| nº| System call         |
|---|---------------------|
| 0 | write() system call |
| 1 | read() system call  |
| 2 | open() system call  |
| 3 | close() system call  |
| 4 | dup() system call |
| 5 | dup2() system call |
| 6 | fork() system call |
| 7 | getpid() system call |
| 8 | lseek() system call |
| 9 | mmap() system call |
