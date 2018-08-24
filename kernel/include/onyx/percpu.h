/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_PERCPU_H
#define _ONYX_PERCPU_H

#include <stdint.h>

#define PER_CPU_VAR(var) __attribute__((section(".percpu"), used))	var


extern char __percpu_start;
extern char __percpu_end;

#define CPU_OFFSET(var)	(uintptr_t) &var - (uintptr_t) &__percpu_start

void *__do_get_per_cpu(uintptr_t offset);
void setup_percpu(void);

#define GET_PER_CPU(var, type)	*(type*) __do_get_per_cpu(CPU_OFFSET(var))
#define GET_PER_CPU_ADDR(var)		__do_get_per_cpu(CPU_OFFSET(var))

#endif
