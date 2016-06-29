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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <kernel/task_switching.h>
#include <kernel/vmm.h>
#include <kernel/spinlock.h>
#include <kernel/panic.h>
#include <kernel/tss.h>
// First and last nodes of the linked list
static volatile thread_t* firstThread = NULL;
static volatile thread_t* lastThread = NULL;
static volatile thread_t* currentThread = NULL;
/* Creates a thread for the scheduler to switch to
   Expects a callback for the code(RIP) and some flags */
thread_t* sched_create_thread(ThreadCallback callback, uint32_t flags,void* args)
{
	thread_t* newThread = malloc(sizeof(thread_t));
	newThread->rip = callback;
	newThread->flags = flags;
	if(!(flags & 1)) // If the thread is user mode, create a user stack
		newThread->user_stack = (uintptr_t*)vmm_allocate_virt_address(0, 2, VMM_TYPE_REGULAR);
	newThread->kernel_stack = (uintptr_t*)vmm_allocate_virt_address(VM_KERNEL, 2, VMM_TYPE_REGULAR);
	printf("kernel stack: %p\nuser_stack: %p\n",newThread->kernel_stack, newThread->user_stack);
	// Map the stacks on the virtual address space
	if(!(flags & 1))
		vmm_map_range(newThread->user_stack, 2, 0x3 | 0x80);
	vmm_map_range(newThread->kernel_stack, 2, 0x3);
	// Increment the stacks by 8 KiB
	{
	char** stack = (char**)&newThread->user_stack;
	if(!(flags & 1))
		*stack+=0x2000;
	stack = (char**)&newThread->kernel_stack;
	*stack+=0x2000;
	}
	uint64_t* stack = NULL;
	// Reserve space in the stacks for the registers that are popped during a switch
	stack = newThread->kernel_stack;
	newThread->kernel_stack_top = stack;
	newThread->user_stack_top = newThread->user_stack;
	uintptr_t originalStack = (uintptr_t)stack;
	if(!(flags & 1))
		originalStack = (uintptr_t)newThread->user_stack;
	uint64_t ds = 0x10, cs = 0x08;
	if(!(flags & 1))
		ds = 0x23, cs = 0x1b;
	*--stack = ds; //SS
	*--stack = originalStack; //RSP
	*--stack = 0x202; // RFLAGS
	*--stack = cs; //CS
	*--stack = (uint64_t) callback; //RIP
	*--stack = 0; // RAX
	*--stack = 0; // RBX
	*--stack = 0; // RCX
	*--stack = 0; // RDX
	*--stack = (uint64_t) args; // RDI
	*--stack = 0; // RSI
	*--stack = 0; // R15
	*--stack = 0; // R14
	*--stack = 0; // R13
	*--stack = 0; // R12
	*--stack = 0; // R11
	*--stack = 0; // R10
	*--stack = 0; // R9
	*--stack = 0; // R8
	*--stack = ds; // DS
	newThread->kernel_stack = stack;
	if(!firstThread)
		firstThread = newThread;

	if(!lastThread)
		lastThread = newThread;
	else
		lastThread->next = newThread;
	lastThread = newThread;
	return newThread;
}
void* sched_switch_thread(void* last_stack)
{
	//printf("Switching\n");
	if(!currentThread)
	{
		currentThread = firstThread;
		set_kernel_stack((uintptr_t)currentThread->kernel_stack);
		return currentThread->kernel_stack;
	}
	else
	{
		currentThread->kernel_stack = (uintptr_t*)last_stack;
		if(currentThread->next)
			currentThread = currentThread->next;
		else
			currentThread = firstThread;
		set_kernel_stack((uintptr_t)currentThread->kernel_stack);
		return currentThread->kernel_stack;
	}
}
thread_t *get_current_thread()
{
	return (thread_t*)currentThread;
}
