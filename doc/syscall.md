# System Calls

The kernel exposes the system calls to the user-space by the interrupt vector 0x80 ( 128 decimal ). In the future, syscall will be supported.

## Table of System calls

| nº| System call         |
|---|---------------------|
| 0 | write() system call |
| 1 | read() system call  |
| 2 | exit() system call  |
| 3 | abort() system call |
| 4 | exec() system call  |
| 5 | fork() system call  |
| 6 | wait() system call  |

## NOTE: This is just a draft, and there will be many more system calls, but these are the basic ones