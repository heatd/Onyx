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
#include <stdbool.h>

#include <kernel/data_structures.h>
#include <kernel/task_switching.h>
#include <kernel/vmm.h>
#include <kernel/spinlock.h>
#include <kernel/panic.h>
#include <kernel/tss.h>
#include <kernel/process.h>

static queue_t *running_queue = NULL;
static thread_t *idle_thread = NULL; 
static thread_t *current_thread = NULL;
static _Bool is_initialized = false;
/* Creates a thread for the scheduler to switch to
   Expects a callback for the code(RIP) and some flags */
int curr_id = 1;
thread_t* task_switching_create_context(thread_callback_t callback, uint32_t flags, void* args)
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
	char** stack = (char**) &new_thread->user_stack;

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

	uintptr_t original_stack = (uintptr_t)stack;
	if(!(flags & 1))
		original_stack = (uintptr_t)new_thread->user_stack;

	uint64_t ds = 0x10, cs = 0x08, rf = 0x202;
	if(!(flags & 1))
		ds = 0x23, cs = 0x1b, rf = 0x202;

	*--stack = ds; //SS
	*--stack = original_stack; //RSP
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
	
	return new_thread;
}
extern PML4 *current_pml4;
extern vmm_entry_t *areas;
extern size_t num_areas;
thread_t* task_switching_create_main_progcontext(thread_callback_t callback, uint32_t flags,int argc, char **argv, char **envp)
{
	thread_t* new_thread = malloc(sizeof(thread_t));
	
	if(!new_thread)
		return NULL;
	
	memset(new_thread, 0, sizeof(thread_t));
	
	new_thread->rip = callback;
	new_thread->flags = flags;
	new_thread->id = curr_id++;
	
	if(!(flags & 1)) // If the thread is user mode, create a user stack
	{
		new_thread->user_stack = (uintptr_t*)vmm_allocate_virt_address(0, 256, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC | VMM_USER);
		if(!new_thread->user_stack)
			return NULL;
	}
	
	new_thread->kernel_stack = (uintptr_t*)vmm_allocate_virt_address(VM_KERNEL, 4, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC);
	
	if(!new_thread->kernel_stack)
	{
		if(new_thread->user_stack)
		{
			vmm_destroy_mappings(new_thread->user_stack, 256);
		}
		return NULL;
	}
	
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
	
	uintptr_t original_stack = (uintptr_t)stack;
	if(!(flags & 1))
		original_stack = (uintptr_t)new_thread->user_stack;
	
	uint64_t ds = 0x10, cs = 0x08, rf = 0x202;
	if(!(flags & 1))
		ds = 0x23, cs = 0x1b, rf = 0x202;
	
	*--stack = ds; //SS
	*--stack = original_stack; //RSP
	*--stack = rf; // RFLAGS
	*--stack = cs; //CS
	*--stack = (uint64_t) callback; //RIP
	*--stack = 0; // RAX
	*--stack = 0; // RBX
	*--stack = 0; // RCX
	*--stack = (uint64_t) envp; // RDX
	*--stack = (uint64_t) argc; // RDI
	*--stack = (uint64_t) argv; // RSI
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
	
	return new_thread;
}
void* sched_switch_thread(void* last_stack)
{
	if(is_initialized == 0)
	{
		return last_stack;
	}
	if(!running_queue)
	{
		/* TODO: Add multiprocessor support */
		printf("Returning idle thread!\n");
		current_thread = idle_thread;
		set_kernel_stack((uintptr_t) current_thread->kernel_stack_top);
		return idle_thread->kernel_stack;
	}
	if(!current_thread)
	{
		current_thread = running_queue->data;
		free(running_queue);
		running_queue = running_queue->next;	
	}
	current_thread->kernel_stack = (uintptr_t*)last_stack;
	if(current_process)
	{
		current_process->areas = areas;
		current_process->num_areas = num_areas;
	}
	if(!running_queue)
	{
		running_queue = malloc(sizeof(queue_t));
		running_queue->data = current_thread;
		running_queue->prev = NULL;
		running_queue->next = NULL;
	}
	else
	{
		queue_add_to_tail(running_queue, current_thread);
	}
	/* Get a thread from the queue */
	current_thread = running_queue->data;
	free(running_queue);
	running_queue = running_queue->next;
	
	/* Fill the TSS with a kernel stack*/
	set_kernel_stack((uintptr_t)current_thread->kernel_stack_top);
	current_process = current_thread->owner;
	if(current_process)
	{
		areas = current_process->areas;
		num_areas = current_process->num_areas;
		
		if (current_pml4 != current_process->cr3)
		{
			paging_load_cr3(current_process->cr3);
		}
		
		wrmsr(FS_BASE_MSR, (uintptr_t)current_process->fs & 0xFFFFFFFF, (uintptr_t)current_process->fs >> 32);
	}
	return current_thread->kernel_stack;
}
thread_t *get_current_thread()
{
	return (thread_t*)current_thread;
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
	*--stack = forkstackregs[13]; // RBX
	*--stack = forkstackregs[12]; // RCX
	*--stack = forkstackregs[11]; // RDX
	*--stack = forkstackregs[10]; // RDI
	*--stack = forkstackregs[9]; // RSI
	*--stack = forkstackregs[8]; // RBP
	*--stack = forkstackregs[7]; // R15
	*--stack = forkstackregs[6]; // R14
	*--stack = forkstackregs[5]; // R13
	*--stack = forkstackregs[4]; // R12
	*--stack = forkstackregs[3]; // R11
	*--stack = forkstackregs[2]; // R10
	*--stack = forkstackregs[1]; // R9
	*--stack = forkstackregs[0]; // R8
	*--stack = ss; // DS
	
	return stack; 
}
void sched_idle()
{
	/* This function will not do work at all, just idle using hlt*/
	for(;;)
		asm volatile("hlt");
}
thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void* args)
{
	/* Create the thread context (aka the real work) */
	thread_t *t = task_switching_create_context(callback, flags, args);
	if(!t)
		return NULL;
	/* Add it to the queue */
	if(unlikely(!running_queue))
	{
		running_queue = malloc(sizeof(queue_t));
		if(unlikely(!running_queue))
			panic("sched_create_thread: no memory for 'running_queue'");
		memset(running_queue, 0, sizeof(queue_t));
		running_queue->data = t;
	}
	else
	{
		queue_add_to_tail(running_queue, t);
	}
	return t;
}
thread_t* sched_create_main_thread(thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp)
{
	/* Create the thread context (aka the real work) */
	thread_t *t = task_switching_create_main_progcontext(callback, flags, argc, argv, envp);
	if(!t)
		return NULL;
	/* Add it to the queue */
	if(unlikely(!running_queue))
	{
		running_queue = malloc(sizeof(queue_t));
		if(unlikely(!running_queue))
			panic("sched_create_thread: no memory for 'running_queue'");
		memset(running_queue, 0, sizeof(queue_t));
		running_queue->data = t;
	}
	else
	{
		queue_add_to_tail(running_queue, t);
	}
	return t;
}
int sched_init()
{
	idle_thread = sched_create_thread(sched_idle, 1, NULL);
	if(!idle_thread)
			return 1;
	is_initialized = true;
	return 0;
}