/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef SYSCALL_H
#define SYSCALL_H
#include <errno.h>
// The Spartix kernel's system call numbers
#define SYS_write	0
#define SYS_read 	1
#define SYS_open 	2
#define SYS_close 	3
#define SYS_dup  	4
#define SYS_dup2 	5
#define SYS_getpid	6
#define SYS_lseek	7
#define SYS_exit	8
#define SYS_posix_spawn	9
#define SYS_fork	10
#define SYS_mmap	11
#define SYS_munmap	12
#define SYS_mprotect	13
#define SYS_mount	14
#define SYS_execve	15
#define SYS_brk		16
#define SYS_kill	17
#define SYS_getppid	18
#define SYS_wait	19	
#define SYS_time	20
#define SYS_gettimeofday 21
#define SYS_reboot	22
#define SYS_shutdown	23
#define SYS_readv	24
#define SYS_writev	25
#define SYS_preadv	26
#define SYS_pwritev	27
#define SYS_getdents	28
#define SYS_ioctl	29
#define SYS_truncate	30
#define SYS_ftruncate	31
#define SYS_personality	32
#define SYS_signal	33
#define SYS_isatty	34
#define set_errno() register int __err asm("r11"); \
errno = __err

#define __syscall0(no) __asm__ __volatile__("int $0x80" :"=a"(rax) :"a"(no):"memory")
#define __syscall1(no, a) __asm__ __volatile__("int $0x80" :"=a"(rax) :"a"(no), "D"(a) : "memory")
#define __syscall2(no, a, b) __asm__ __volatile__("int $0x80" :"=a"(rax) :"a"(no), "D"(a), "S"(b) : "memory")
#define __syscall3(no, a, b, c) __asm__ __volatile__("int $0x80" :"=a"(rax) :"a"(no), "D"(a), "S"(b), "d"(c) : "memory")
#define __syscall4(no, a, b, c, d) __asm__ __volatile__("int $0x80":"=a"(rax) :"a"(no), "D"(a), "S"(b), "d"(c), "c"(d) : "memory")
#define __syscall5(no, a, b, c, d, e) __asm__ __volatile__("mov %0, %r8;int $0x80":"=a"(rax) :"r"(e), a"(no), "D"(a), "S"(b), "d"(c), "c"(d) : "memory")
#define __syscall6(no, a, b, c, d, e, f) __asm__ __volatile__("mov %0, %r8;mov %1, %r9;int $0x80":"=a"(rax) :"r"(e), "r"(f), "a"(no), "D"(a), "S"(b), "d"(c), "c"(d) : "memory")

#define MKFN(fn,...) MKFN_N(fn,##__VA_ARGS__,9,8,7,6,5,4,3,2,1,0)(__VA_ARGS__)
#define MKFN_N(fn,NR,n0,n1,n2,n3,n4,n5,n6,n7,n8,n,...) fn##n

#define syscall(...) register unsigned long rax asm ("rax"); \
MKFN(__syscall, ##__VA_ARGS__); \

#endif
