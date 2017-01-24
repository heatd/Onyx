/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
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

#include <kernel/timer.h>
#include <kernel/data_structures.h>
#include <kernel/task_switching.h>
#include <kernel/vmm.h>
#include <kernel/spinlock.h>
#include <kernel/panic.h>
#include <kernel/tss.h>
#include <kernel/process.h>
#include <kernel/idt.h>
#include <kernel/elf.h>
#include <kernel/fpu.h>
#include <kernel/apic.h>
#include <kernel/cpu.h>

static thread_t *run_queue = NULL;
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
	/*new_thread->fxsave = malloc(512);
	memset(new_thread->fxsave, 0, 512);*/
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
	new_thread->user_stack_bottom = new_thread->user_stack;
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

	uintptr_t original_stack = (uintptr_t)stack;
	if(!(flags & 1))
		original_stack = (uintptr_t)new_thread->user_stack;

	uint64_t ds = 0x10, cs = 0x08, rf = 0x202;
	if(!(flags & 1))
		ds = 0x2b, cs = 0x33, rf = 0x202;

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
thread_t* task_switching_create_main_progcontext(thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp)
{
	thread_t* new_thread = malloc(sizeof(thread_t));
	
	if(!new_thread)
		return NULL;
	
	memset(new_thread, 0, sizeof(thread_t));
	/*new_thread->fxsave = malloc(512);
	memset(new_thread->fxsave, 0, 512);*/
	new_thread->rip = callback;
	new_thread->flags = flags;
	new_thread->id = curr_id++;
	
	if(!(flags & 1)) // If the thread is user mode, create a user stack
	{
		new_thread->user_stack = (uintptr_t*)vmm_allocate_virt_address(0, 256, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC | VMM_USER);
		if(!new_thread->user_stack)
			return NULL;
	}
	
	new_thread->kernel_stack = (uintptr_t*)vmm_allocate_virt_address(VM_KERNEL, 2, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC);
	
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
	vmm_map_range(new_thread->kernel_stack, 2, VMM_WRITE | VMM_NOEXEC);
	new_thread->user_stack_bottom = new_thread->user_stack;
	// Increment the stacks by 8 KiB
	{
	char** stack = (char**)&new_thread->user_stack;
	
	if(!(flags & 1))
		*stack+=0x100000;
	
	stack = (char**)&new_thread->kernel_stack;
	*stack+=0x2000;
	}
	
	uint64_t* stack = NULL;
	// Reserve space in the stacks for the registers that are popped during a switch
	stack = new_thread->kernel_stack;
	
	new_thread->kernel_stack_top = stack;
	
	uintptr_t original_stack = (uintptr_t)stack;
	if(!(flags & 1))
		original_stack = (uintptr_t)new_thread->user_stack;
	
	uint64_t ds = 0x10, cs = 0x08, rf = 0x202;
	if(!(flags & 1))
		ds = 0x33, cs = 0x2b, rf = 0x202;
	
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
thread_t *sched_find_runnable(void)
{
	thread_t *t = current_thread->next;
	if(!t)
		t = run_queue;
	while(t)
	{
		if(t->status == THREAD_RUNNABLE)
		{
			return t;
		}
		if(t->status == THREAD_SLEEPING && t->timestamp + t->sleeping_for == get_tick_count())
		{
			t->status = THREAD_RUNNABLE;
			t->timestamp = 0;
			t->sleeping_for = 0;
			return t;
		}
		if(t->status == THREAD_SLEEPING && t->timestamp + t->sleeping_for < get_tick_count() && t->timestamp)
		{
			t->status = THREAD_RUNNABLE;
			t->timestamp = 0;
			t->sleeping_for = 0;
			return t;
		}
		t = t->next;
	}
	return idle_thread;
}
void* sched_switch_thread(void* last_stack)
{
	if(is_initialized == 0)
	{
		return last_stack;
	}
	struct processor *p = get_gs_data();
	/* TODO: Add multiprocessor support */
	if(unlikely(!current_thread))
	{
		current_thread = run_queue;
		set_kernel_stack((uintptr_t)current_thread->kernel_stack_top);
		p->kernel_stack = current_thread->kernel_stack_top;
		return current_thread->kernel_stack;
	}
	current_thread->kernel_stack = (uintptr_t*)last_stack;
	if(likely(current_process))
	{
		current_process->tree = vmm_get_tree();
	}

	/* Save the FPU state */
	SAVE_FPU(current_thread->fpu_area);

	current_thread = sched_find_runnable();
	p->kernel_stack = current_thread->kernel_stack_top;
	/* Fill the TSS with a kernel stack*/
	set_kernel_stack((uintptr_t)current_thread->kernel_stack_top);

	/* Restore the FPU state */
	RESTORE_FPU(current_thread->fpu_area);
	current_process = current_thread->owner;
	if(current_process)
	{
		vmm_set_tree(current_process->tree);
		
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
uintptr_t *sched_fork_stack(syscall_ctx_t *ctx, uintptr_t *stack)
{
	uint64_t rflags = ctx->r11; // Get the RFLAGS, CS and SS
	uint64_t ds = ctx->ds;
	uint64_t cs = ds - 8;

	// Set up the stack.
	*--stack = ds; //SS
	uintptr_t user_stack = (uintptr_t) get_gs_data()->scratch_rsp_stack;
	*--stack = user_stack; //RSP
	*--stack = rflags; // RFLAGS
	*--stack = cs; //CS
	*--stack = ctx->rcx; //RIP
	*--stack = 0; // RAX
	*--stack = ctx->rbx; // RBX
	*--stack = ctx->rcx; // RCX
	*--stack = ctx->rdx; // RDX
	*--stack = ctx->rdi; // RDI
	*--stack = ctx->rsi; // RSI
	*--stack = ctx->rbp; // RBP
	*--stack = ctx->r15; // R15
	*--stack = ctx->r14; // R14
	*--stack = ctx->r13; // R13
	*--stack = ctx->r12; // R12
	*--stack = ctx->r11; // R11
	*--stack = ctx->r10; // R10
	*--stack = ctx->r9; // R9
	*--stack = ctx->r8; // R8
	*--stack = ds; // DS

	return stack; 
}
void sched_idle()
{
	/* This function will not do work at all, just idle using hlt */
	for(;;)
	{
		asm volatile("hlt");
	}
}
void thread_add(thread_t *add)
{
	thread_t *it = current_thread;
	while(it->next)
		it = it->next;
	it->next = add;
}
thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void* args)
{
	/* Create the thread context (aka the real work) */
	thread_t *t = task_switching_create_context(callback, flags, args);
	if(!t)
		return NULL;
	/* Add it to the queue */
	if(unlikely(!run_queue))
	{
		run_queue = t;
	}
	else
	{
		thread_add(t);
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
	if(unlikely(!run_queue))
	{
		run_queue = t;
	}
	else
	{
		thread_add(t);
	}
	return t;
}
extern void _sched_yield();
int sched_init()
{
	idle_thread = task_switching_create_context(sched_idle, 1, NULL);
	if(!idle_thread)
		return 1;
	is_initialized = true;
	return 0;
}
void sched_yield()
{
	asm volatile("int $0x81");
}
void sched_sleep(unsigned long ms)
{
	current_thread->timestamp = get_tick_count();
	current_thread->sleeping_for = ms;
	current_thread->status = THREAD_SLEEPING;
	sched_yield();
}
void sched_destroy_thread(thread_t *thread)
{
	thread_t *it = run_queue;
	for(; it->next; it = it->next)
	{
		if(it->next == thread)
		{
			printf("Deleted %p\n", thread);
			it->next = thread->next;
			free(thread);
			return;
		}
	}
}
