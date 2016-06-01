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
// First and last nodes of the linked list
static Thread* firstThread = nullptr;
static Thread* lastThread = nullptr;
static Thread* currentThread = nullptr;
/* Creates a thread for the scheduler to switch to
   Expects a callback for the code(RIP) and some flags */
static spinlock_t spl;
Thread* NativeSchedulerCreateThread(ThreadCallback callback, uint32_t flags,void* args)
{
	acquire(&spl);
	Thread* newThread = new Thread;
	newThread->rip = callback;
	newThread->flags = flags;
	if(!(flags & 1)) // If the thread is user mode, create a user stack
		newThread->userStack = (uintptr_t*)VirtualMemoryManager::AllocateVirtAddress(VM_KERNEL, 2);
	newThread->kernelStack = (uintptr_t*)VirtualMemoryManager::AllocateVirtAddress(VM_KERNEL, 2);
	if(!(flags & 1))
	// Map the stacks on the virtual address space
	if(!(flags & 1))
		VirtualMemoryManager::MapRange(newThread->userStack, 2);
	VirtualMemoryManager::MapRange(newThread->kernelStack, 2);
	// Increment the stacks by 8 KiB
	{
	char** stack = (char**)&newThread->userStack;
	if(!(flags & 1))
		*stack+=0x2000;
	stack = (char**)&newThread->kernelStack;
	*stack+=0x2000;
	}
	uint64_t* stack = nullptr;
	// Reserve space in the stacks for the registers that are popped during a switch
	if(!(flags & 1))
	{
		stack = newThread->userStack;
		uintptr_t originalStack = (uintptr_t)stack;
		*--stack = 0x1B; //SS
		*--stack = originalStack + 8; //RSP
		*--stack = 0x0202; //RFLAGS
		*--stack = 0x23; //CS
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
	}
	stack = newThread->kernelStack;
	uintptr_t originalStack = (uintptr_t)stack;
	*--stack = 0x10; //SS
	*--stack = originalStack + 8; //RSP
	*--stack = 0x0202; //RFLAGS
	*--stack = 0x8; //CS
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

	newThread->kernelStack = stack;
	if(!firstThread)
		firstThread = newThread;

	if(!lastThread)
		lastThread = newThread;
	else
		lastThread->next = newThread;
	lastThread = newThread;
	release(&spl);
	return newThread;
}
extern "C" void* NativeSchedulerSwitchThread(void* lastStack)
{
	if(!currentThread)
	{
		currentThread = firstThread;
		return currentThread->kernelStack;
	}
	else
	{
		currentThread->kernelStack = (uintptr_t*)lastStack;
		if(currentThread->next)
			currentThread = currentThread->next;
		else
			currentThread = firstThread;
		return currentThread->kernelStack;
	}
}
