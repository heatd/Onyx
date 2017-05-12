/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _FPU_H
#define _FPU_H

#include <stdbool.h>
#ifdef __x86_64__

#define FPU_AREA_ALIGNMENT 	64
#define FPU_AREA_SIZE		2048

extern _Bool avx_supported;

#else
#error "Implement FPU switching for your arch"
#endif

void save_fpu(void *address);
void restore_fpu(void *address);
#endif