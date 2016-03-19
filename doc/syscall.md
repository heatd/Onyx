# System Calls

The kernel exposes the system calls to the user-space by the interrupt vector 0x80 ( 128 decimal ). In the future, syscall will be supported.

## Table of System calls

| nº| System call         |
|---|---------------------|
| 0 | write() system call |
| 1 | read() system call  |
| 2 | yield() system call |
| 3 | sbrk() system call  |
| 4 | fork() system call  |
| 5 | getpid() system call |
