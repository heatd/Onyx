/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_X86_KTRACE_H
#define _ONYX_X86_KTRACE_H

#include <onyx/registers.h>

#ifdef __cplusplus
extern "C" {
#endif

void ktrace_int3_handler(struct registers *regs);

#ifdef __cplusplus
}
#endif

#endif