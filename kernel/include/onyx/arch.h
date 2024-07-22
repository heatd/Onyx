/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_ARCH_H
#define _ONYX_ARCH_H

#include <stddef.h>

#include <onyx/process.h>
#include <onyx/thread.h>

void arch_vm_init(void);

#ifdef __cplusplus

namespace native
{

void arch_save_thread(thread *thread, void *stack);
void arch_load_thread(thread *thread, unsigned int cpu);
void arch_load_process(process *process, thread *thread, unsigned int cpu);

}; // namespace native

#endif

#endif
