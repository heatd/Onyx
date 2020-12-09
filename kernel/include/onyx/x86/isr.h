/*
* Copyright (c) 2016-2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_X86_ISR_H
#define _ONYX_X86_ISR_H

#include <stdlib.h>
#include <onyx/registers.h>

#ifdef __cplusplus
extern "C" {
#endif

void ktrace_enable_int3(void);
void ktrace_disable_int3(void);

#define EXCEPTION_VECTORS_END       32

#define INTERRUPT_STACK_ALIGN(regs) (((unsigned long) regs) - 8)

unsigned long irq_handler(struct registers *regs);

#ifdef __cplusplus
}
#endif

#endif
