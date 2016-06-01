/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/

 #ifndef _TASK_SWITCHING_AMD64_H
 #define _TASK_SWITCHING_AMD64_H

typedef void(*ThreadCallback)(void*);
typedef struct thr
{
	uintptr_t* userStack;
	uintptr_t* kernelStack;
	ThreadCallback rip;
	uint32_t flags;
	struct thr* next;
} Thread;
Thread* NativeSchedulerCreateThread(ThreadCallback callback, uint32_t flags, void* args);

 #endif
