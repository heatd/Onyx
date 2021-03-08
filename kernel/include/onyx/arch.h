/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_ARCH_H
#define _ONYX_ARCH_H

#include <stddef.h>

#include <onyx/thread.h>
#include <onyx/process.h>

size_t arch_heap_get_size(void);
size_t arch_get_initial_heap_size(void);
void arch_vm_init(void);

#ifdef __cplusplus

namespace native
{

void arch_save_thread(thread *thread, void *stack);
void arch_load_thread(thread *thread, unsigned int cpu);
void arch_load_process(process *process, thread *thread,
                       unsigned int cpu);

};

#endif

#endif
