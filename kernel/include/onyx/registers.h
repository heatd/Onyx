/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_REGISTERS_H
#define _KERNEL_REGISTERS_H

#ifdef __x86_64__

#ifndef __ASSEMBLER__

typedef struct registers
{
	unsigned long ds;
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rbp;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long rdx;
	unsigned long rcx;
	unsigned long rbx;
	unsigned long rax;
	unsigned long int_no;
	unsigned long int_err_code;
	unsigned long rip;
	unsigned long cs;
	unsigned long rflags;
	unsigned long rsp;
	unsigned long ss;
} registers_t;

#endif

#define REGISTER_OFF_DS			0
#define REGISTER_OFF_R15		8
#define REGISTER_OFF_R14		16
#define REGISTER_OFF_R13		24
#define REGISTER_OFF_R12		32
#define REGISTER_OFF_R11		40
#define REGISTER_OFF_R10		48
#define REGISTER_OFF_R9			56
#define REGISTER_OFF_R8			64
#define REGISTER_OFF_RBP		72
#define REGISTER_OFF_RSI		80
#define REGISTER_OFF_RDI		88
#define REGISTER_OFF_RDX		96
#define REGISTER_OFF_RCX		104
#define REGISTER_OFF_RBX		112
#define REGISTER_OFF_RAX		120
#define REGISTER_OFF_INT_NO		128
#define REGISTER_OFF_INT_ERR_CODE	136
#define REGISTER_OFF_RIP		144
#define REGISTER_OFF_CS			152
#define REGISTER_OFF_RFLAGS		160
#define REGISTER_OFF_RSP		168
#define REGISTER_OFF_SS			176

#endif
#endif
