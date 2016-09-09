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
#include <kernel/process.h>
// First and last nodes of the linked list
static volatile thread_t* first_thread = NULL;
volatile thread_t* last_thread = NULL;
static volatile thread_t* current_thread = NULL;
/* Creates a thread for the scheduler to switch to
   Expects a callback for the code(RIP) and some flags */
int curr_id = 1;
thread_t* sched_create_thread(ThreadCallback callback, uint32_t flags,void* args)
{
	thread_t* new_thread = malloc(sizeof(thread_t));
	if(!new_thread)
		panic("OOM while allocating thread");
	memset(new_thread, 0 ,sizeof(thread_t));
	new_thread->rip = callback;
	new_thread->flags = flags;
	new_thread->id = curr_id++;
	if(!(flags & 1)) // If the thread is user mode, create a user stack
		new_thread->user_stack = (uintptr_t*)vmm_allocate_virt_address(0, 256, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	new_thread->kernel_stack = (uintptr_t*)vmm_allocate_virt_address(VM_KERNEL, 4, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC);
	// Map the stacks on the virtual address space
	if(!(flags & 1))
		vmm_map_range(new_thread->user_stack, 256, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	vmm_map_range(new_thread->kernel_stack, 4, VMM_WRITE | VMM_NOEXEC);
	// Increment the stacks by 8 KiB
	{
	char** stack = (char**)&new_thread->user_stack;
	if(!(flags & 1))
		*stack+=0x100000;
	stack = (char**)&new_thread->kernel_stack;
	*stack+=0x4000;
	}
	uint64_t* stack = NULL;
	// Reserve space in the stacks for the registers that are popped during a switch
	stack = new_thread->kernel_stack;
	new_thread->kernel_stack_top = stack;
	new_thread->user_stack_top = new_thread->user_stack;
	uintptr_t originalStack = (uintptr_t)stack;
	if(!(flags & 1))
		originalStack = (uintptr_t)new_thread->user_stack;
	uint64_t ds = 0x10, cs = 0x08, rf = 0x202;
	if(!(flags & 1))
		ds = 0x23, cs = 0x1b, rf = 0x202;
	*--stack = ds; //SS
	*--stack = originalStack; //RSP
	*--stack = rf; // RFLAGS
	*--stack = cs; //CS
	*--stack = (uint64_t) callback; //RIP
	*--stack = 0; // RAX
	*--stack = 0; // RBX
	*--stack = 0; // RCX
	*--stack = 0; // RDX
	*--stack = (uint64_t) args; // RDI
	*--stack = 0; // RSI
	*--stack = 0; // RBP
	*--stack = 0; // R15
	*--stack = 0; // R14
	*--stack = 0; // R13
	*--stack = 0; // R12
	*--stack = 0; // R11
	*--stack = 0; // R10
	*--stack = 0; // R9
	*--stack = 0; // R8
	*--stack = ds; // DS
	new_thread->kernel_stack = stack;
	if(!first_thread)
		first_thread = new_thread;

	if(!last_thread)
		last_thread = new_thread;
	else
		last_thread->next = new_thread;
	last_thread = new_thread;
	return new_thread;
}
thread_t* sched_create_main_thread(ThreadCallback callback, uint32_t flags,int argc, char **argv, char **envp)
{
	thread_t* new_thread = malloc(sizeof(thread_t));
	if(!new_thread)
		panic("OOM while allocating thread");
	memset(new_thread, 0, sizeof(thread_t));
	new_thread->rip = callback;
	new_thread->flags = flags;
	new_thread->id = curr_id++;
	if(!(flags & 1)) // If the thread is user mode, create a user stack
		new_thread->user_stack = (uintptr_t*)vmm_allocate_virt_address(0, 256, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	new_thread->kernel_stack = (uintptr_t*)vmm_allocate_virt_address(VM_KERNEL, 4, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC);
	// Map the stacks on the virtual address space
	if(!(flags & 1))
		vmm_map_range(new_thread->user_stack, 256, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	vmm_map_range(new_thread->kernel_stack, 4, VMM_WRITE | VMM_NOEXEC);
	// Increment the stacks by 8 KiB
	{
	char** stack = (char**)&new_thread->user_stack;
	if(!(flags & 1))
		*stack+=0x100000;
	stack = (char**)&new_thread->kernel_stack;
	*stack+=0x4000;
	}
	uint64_t* stack = NULL;
	// Reserve space in the stacks for the registers that are popped during a switch
	stack = new_thread->kernel_stack;
	new_thread->kernel_stack_top = stack;
	new_thread->user_stack_top = new_thread->user_stack;
	uintptr_t originalStack = (uintptr_t)stack;
	if(!(flags & 1))
		originalStack = (uintptr_t)new_thread->user_stack;
	uint64_t ds = 0x10, cs = 0x08, rf = 0x202;
	if(!(flags & 1))
		ds = 0x23, cs = 0x1b, rf = 0x202;
	*--stack = ds; //SS
	*--stack = originalStack; //RSP
	*--stack = rf; // RFLAGS
	*--stack = cs; //CS
	*--stack = (uint64_t) callback; //RIP
	*--stack = 0; // RAX
	*--stack = 0; // RBX
	*--stack = 0; // RCX
	*--stack = (uint64_t) envp; // RDX
	*--stack = (uint64_t) argc; // RDI
	*--stack = (uint64_t)argv; // RSI
	*--stack = 0; // RBP
	*--stack = 0; // R15
	*--stack = 0; // R14
	*--stack = 0; // R13
	*--stack = 0; // R12
	*--stack = 0; // R11
	*--stack = 0; // R10
	*--stack = 0; // R9
	*--stack = 0; // R8
	*--stack = ds; // DS
	new_thread->kernel_stack = stack;
	if(!first_thread)
		first_thread = new_thread;

	if(!last_thread)
		last_thread = new_thread;
	else
		last_thread->next = new_thread;
	last_thread = new_thread;
	return new_thread;
}
void* sched_switch_thread(void* last_stack)
{
	if(!current_thread)
	{
		current_thread = first_thread;
		set_kernel_stack((uintptr_t)current_thread->kernel_stack_top);
		return current_thread->kernel_stack;
	}
	else
	{
		current_thread->kernel_stack = (uintptr_t*)last_stack;
		if(current_process)
		{
			extern vmm_entry_t *areas;
			extern size_t num_areas;
			current_process->areas = areas;
			current_process->num_areas = num_areas;
		}
		if(current_thread->next)
			current_thread = current_thread->next;
		else
			current_thread = first_thread;
		if(first_thread->next && current_thread == first_thread)
			current_thread = first_thread->next;
		set_kernel_stack((uintptr_t)current_thread->kernel_stack_top);
		current_process = current_thread->owner;
		if(current_process)
		{
			extern vmm_entry_t *areas;
			extern size_t num_areas;
			areas = current_process->areas;
			num_areas = current_process->num_areas;
			extern PML4 *current_pml4;
			if (current_pml4 != current_process->cr3)
			{
				paging_load_cr3(current_process->cr3);
			}
		}
		return current_thread->kernel_stack;
	}
}
thread_t *get_current_thread()
{
	return (thread_t*)current_thread;
}
void sched_destroy_thread(thread_t *thread)
{
	for(volatile thread_t *i = first_thread; i; i=i->next)
	{
		if(i->next == thread)
		{
			i->next = thread->next;
			break;
		}
	}
	//paging_unmap(thread->kernel_stack_top - 0x2000, 2);
	//paging_unmap(thread->user_stack_top - 0x2000, 1024);
	free(thread);
}
uintptr_t *sched_fork_stack(uintptr_t *stack, uintptr_t *forkstackregs, uintptr_t *rsp, uintptr_t rip)
{
	uint64_t rflags = forkstackregs[16]; // Get the RFLAGS, CS and SS
	uint64_t cs = forkstackregs[15];
	uint64_t ss = forkstackregs[18];

	// Set up the stack.
	*--stack = ss; //SS
	*--stack = (uintptr_t) rsp; //RSP
	*--stack = rflags; // RFLAGS
	*--stack = cs; //CS
	*--stack = rip; //RIP
	*--stack = 0; // RAX
	*--stack = forkstackregs[12]; // RBX
	*--stack = forkstackregs[11]; // RCX
	*--stack = forkstackregs[10]; // RDX
	*--stack = forkstackregs[9]; // RDI
	*--stack = forkstackregs[8]; // RSI
	*--stack = forkstackregs[7]; // RBP
	*--stack = forkstackregs[6]; // R15
	*--stack = forkstackregs[5]; // R14
	*--stack = forkstackregs[4]; // R13
	*--stack = forkstackregs[3]; // R12
	*--stack = 0;
	*--stack = forkstackregs[2]; // R10
	*--stack = forkstackregs[1]; // R9
	*--stack = forkstackregs[0]; // R8
	*--stack = ss; // DS
	
	return stack; 
}
