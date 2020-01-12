/*
* Copyright (c) 2016, 2017 Pedro Falcato
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
void ktrace_disable_int3(void)

#ifdef __cplusplus
}
#endif

#endif
