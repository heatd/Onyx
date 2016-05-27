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

#define TERMINAL_WRITE_SYSCALL 0L
#define FORK_SYSCALL 	1L
#define EXIT_SYSCALL 	2L
#define MMAP_SYSCALL 	3L
#define EXEC_SYSCALL 	4L
#define ABORT_SYSCALL 	5L

#ifdef __i386__
#define SYSCALL(intno,ebxr,ecxr,edxr,edir,esir) \
__asm__ __volatile__("movl %0,%%eax"::"a"(intno)); \
__asm__ __volatile__("movl %0,%%ebx"::"a"(ebxr)); \
__asm__ __volatile__("movl %0,%%ecx"::"a"(ecxr)); \
__asm__ __volatile__("movl %0,%%edx"::"a"(edxr)); \
__asm__ __volatile__("movl %0,%%edi"::"a"(edir)); \
__asm__ __volatile__("movl %0,%%esi"::"a"(esir)); \
__asm__ __volatile__("int $0x80");
#endif
#ifdef __x86_64__
#define SYSCALL(intno,rbxr,rcxr,rdxr,rdir,rsir) \
__asm__ __volatile__("movq %0,%%rax"::"a"(intno)); \
__asm__ __volatile__("movq %0,%%rbx"::"a"(rbxr)); \
__asm__ __volatile__("movq %0,%%rcx"::"a"(rcxr)); \
__asm__ __volatile__("movq %0,%%rdx"::"a"(rdxr)); \
__asm__ __volatile__("movq %0,%%rdi"::"a"(rdir)); \
__asm__ __volatile__("movq %0,%%rsi"::"a"(rsir)); \
__asm__ __volatile__("int $0x80");
#endif
#endif
