/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_THREAD_H
#define _KERNEL_THREAD_H

#include <kernel/task_switching.h>
#ifdef __cplusplus
extern "C" {
#endif
thread_t *sched_spawn_thread(registers_t *regs, thread_callback_t start, void *arg, void *fs);
#ifdef __cplusplus
}
#endif
#endif
