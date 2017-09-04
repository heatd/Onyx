/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_REGISTERS_H
#define _KERNEL_REGISTERS_H
#include <stdint.h>
#ifdef __x86_64__
typedef struct registers
{
	uint64_t ds;
	uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rbp, rsi, rdi, rdx, rcx, rbx, rax;
	uint64_t rip;
	uint64_t cs;
	uint64_t rflags;
	uint64_t rsp;
	uint64_t ss;
} registers_t;
typedef struct
{
	uint64_t ds;
	uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rbp, rsi, rdi, rdx, rcx, rbx, rax;
	uint64_t int_no;
	uint64_t err_code;
	uint64_t rip;
	uint64_t cs;
	uint64_t rflags;
	uint64_t rsp;
	uint64_t ss;
} intctx_t;
typedef struct
{
	uint64_t ds;
	uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rbp, rsi, rdi, rdx, rcx, rbx;
	uint64_t rip;
	uint64_t cs;
	uint64_t rflags;
	uint64_t rsp;
	uint64_t ss;
} syscall_ctx_t;
static inline void wrmsr(uint32_t msr, uint32_t lo, uint32_t hi)
{
	__asm__ __volatile__("wrmsr"::"a"(lo), "d"(hi), "c"(msr));
}
static inline void rdmsr(uint32_t msr, uint32_t *lo, uint32_t *hi)
{
	__asm__ __volatile__("rdmsr" : "=a"(*lo), "=d"(*hi) : "c"(msr));
}
#define FS_BASE_MSR 0xC0000100
#define GS_BASE_MSR 0xC0000101
#define KERNEL_GS_BASE 0xC0000102
#define IA32_MSR_STAR 0xC0000081
#define IA32_MSR_LSTAR 0xC0000082
#define IA32_MSR_CSTAR 0xC0000083
#define IA32_MSR_SFMASK 0xC0000084
#else

typedef struct registers
{
   uint32_t eax,ebx,ecx,edx,edi,esi,esp,ebp,eip,eflags,cr3;
   uint16_t ss,cs;
} __attribute__((packed)) registers_t;

#endif /* __x86_64__ */
#endif
