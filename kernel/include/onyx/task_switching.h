/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _TASK_SWITCHING_AMD64_H
#define _TASK_SWITCHING_AMD64_H
#include <stdint.h>

#include <onyx/scheduler.h>
#include <onyx/registers.h>
#include <onyx/fpu.h>

#define THREAD_RUNNABLE		    0
#define THREAD_INTERRUPTIBLE    1
#define THREAD_SLEEPING         2
#define THREAD_IDLE             3
#define THREAD_DEAD             4
#define THREAD_UNINTERRUPTIBLE	5
#define THREAD_STOPPED          6

#endif
