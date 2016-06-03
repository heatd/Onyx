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
#ifndef _CPU_H
#define _CPU_H
#include <stdint.h>
typedef struct cpu {
	char manuid[13];
	char brandstr[48];
	uint32_t max_function;
	uint32_t stepping, family, model, extended_model, extended_family;
	int virtualAddressSpace, physicalAddressSpace;
	/* Add more as needed*/
}cpu_t;
#define CPUID_MANUFACTURERID 		0
#define CPUID_MAXFUNCTIONSUPPORTED 	0x80000000
#define CPUID_BRAND0			0x80000002
#define CPUID_BRAND1 			0x80000003
#define CPUID_BRAND2 			0x80000004
#define CPUID_ASS			0x80000008 // Address space size (ASS for short :P)
#define CPUID_SIGN   			0x1
namespace CPU
{
	void Identify();
	void InitInterrupts();
	void GetAddressSpaceSize(int& vas, int& pas);
}

#endif
