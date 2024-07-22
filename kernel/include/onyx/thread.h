/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _KERNEL_THREAD_H
#define _KERNEL_THREAD_H

#include <onyx/task_switching.h>

thread_t *sched_spawn_thread(registers_t *regs, unsigned int flags, void *fs);

#endif
