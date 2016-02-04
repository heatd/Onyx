# System Calls

The kernel exposes the system calls to the user-space by the interrupt vector 0x80 ( 128 decimal ). In the future, syscall will be supported.

## Table of System calls

| 0 | fork() system call  |
|---|---------------------|
| 1 | write() system call |
| 2 | read() system call  |
| 3 | exit() system call  |
| 4 | abort() system call |
| 5 | exec() system call  |
| 6 | fork() system call  |
| 7 | wait() system call  |

## NOTE: This is just a draft, and there will be many more system calls, but these are the basic ones