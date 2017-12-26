/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include <onyx/timer.h>
#include <onyx/data_structures.h>
#include <onyx/task_switching.h>
#include <onyx/vmm.h>
#include <onyx/spinlock.h>
#include <onyx/panic.h>
#include <onyx/tss.h>
#include <onyx/process.h>
#include <onyx/idt.h>
#include <onyx/elf.h>
#include <onyx/fpu.h>
#include <onyx/apic.h>
#include <onyx/worker.h>
#include <onyx/cpu.h>

#include <sys/time.h>
/* Creates a thread for the scheduler to switch to
   Expects a callback for the code(RIP) and some flags */
int curr_id = 1;

thread_t* task_switching_create_context(thread_callback_t callback, uint32_t flags, void* args)
{
	thread_t* new_thread = malloc(sizeof(thread_t));
	
	if(!new_thread)
		return NULL;
	
	memset(new_thread, 0 ,sizeof(thread_t));

	new_thread->rip = callback;
	new_thread->flags = flags;
	new_thread->id = curr_id++;
	posix_memalign((void**) &new_thread->fpu_area, FPU_AREA_ALIGNMENT, FPU_AREA_SIZE);
	if(!new_thread->fpu_area)
	{
		free(new_thread);
		return NULL;
	}
	memset(new_thread->fpu_area, 0, FPU_AREA_SIZE);
	setup_fpu_area(new_thread->fpu_area);
	if(!(flags & 1)) // If the thread is user mode, create a user stack
		new_thread->user_stack = (uintptr_t*)vmm_allocate_virt_address(VM_ADDRESS_USER, 256, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC | VMM_USER, 0);
	new_thread->kernel_stack = (uintptr_t*)vmm_allocate_virt_address(VM_KERNEL, 4, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC, 0);

	// Map the stacks on the virtual address space
	if(!(flags & 1))
		vmm_map_range(new_thread->user_stack, 256, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	vmm_map_range(new_thread->kernel_stack, 4, VMM_WRITE | VMM_NOEXEC);
	new_thread->user_stack_bottom = new_thread->user_stack;
	// Increment the stacks by 8 KiB
	{
	char** stack = (char**) &new_thread->user_stack;

	if(!(flags & 1))
		*stack += 0x100000;

	stack = (char**)&new_thread->kernel_stack;
	*stack += 0x4000;
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

	new_thread->rip = callback;
	new_thread->flags = flags;
	new_thread->id = curr_id++;
	posix_memalign((void**) &new_thread->fpu_area, FPU_AREA_ALIGNMENT, FPU_AREA_SIZE);
	if(!new_thread->fpu_area)
	{
		free(new_thread);
		return NULL;
	}
	memset(new_thread->fpu_area, 0, FPU_AREA_SIZE);
	setup_fpu_area(new_thread->fpu_area);
	if(!(flags & 1)) // If the thread is user mode, create a user stack
	{
		new_thread->user_stack = (uintptr_t*)vmm_allocate_virt_address(VM_ADDRESS_USER, 256, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC | VMM_USER, 0);
		if(!new_thread->user_stack)
			return NULL;
	}
	
	new_thread->kernel_stack = (uintptr_t*)vmm_allocate_virt_address(VM_KERNEL, 4, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC, 0);
	
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
	new_thread->user_stack_bottom = new_thread->user_stack;
	
	if(!(flags & 1))
	{
		new_thread->user_stack = (uintptr_t*)((uintptr_t) new_thread->user_stack + 0x100000);
	}
	
	new_thread->kernel_stack = (uintptr_t*) ((uintptr_t) new_thread->kernel_stack + 0x4000);

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

uintptr_t *sched_fork_stack(syscall_ctx_t *ctx, uintptr_t *stack)
{
	uint64_t rflags = ctx->r11; // Get the RFLAGS, CS and SS
	uint64_t ds = ctx->ds;
	uint64_t cs = ds - 8;

	// Set up the stack.
	*--stack = ds; //SS
	uintptr_t user_stack = (uintptr_t) get_current_thread()->user_stack;
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

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004
int sys_arch_prctl(int code, unsigned long *addr)
{
	switch(code)
	{
		case ARCH_SET_FS:
		{
			get_current_thread()->fs = (void*) addr;
			wrmsr(FS_BASE_MSR, (uintptr_t)get_current_thread()->fs & 0xFFFFFFFF, (uintptr_t)get_current_thread()->fs >> 32);
			break;
		}
		case ARCH_GET_FS:
		{
			if(copy_to_user(addr, &get_current_thread()->fs, sizeof(unsigned long)) < 0)
				return -EFAULT;
			break;
		}
		case ARCH_SET_GS:
		{
			get_current_thread()->gs = (void*) addr;
			wrmsr(KERNEL_GS_BASE, (uintptr_t)get_current_thread()->gs & 0xFFFFFFFF, (uintptr_t)get_current_thread()->gs >> 32);
			break;
		}
		case ARCH_GET_GS:
		{
			if(copy_to_user(addr, &get_current_thread()->gs, sizeof(unsigned long)) < 0)
				return -EFAULT;
			break;
		}
	}
	return 0;
}

/* Meant to be used on .S files, where structs are hard to access */
void thread_store_ustack(uintptr_t *ustack)
{
	get_current_thread()->user_stack = ustack;
}

uintptr_t *thread_get_ustack(void)
{
	return get_current_thread()->user_stack;
}

void thread_finish_destruction(void *___thread)
{
	thread_t *thread = ___thread;
	/* Destroy the kernel stack */
	vfree((void*) ((uintptr_t)thread->kernel_stack_top - 0x4000), 4);
	
	/* Free the fpu area */
	free(thread->fpu_area);

	/* Free the thread */
	free(thread);
}

thread_t *sched_spawn_thread(registers_t *regs, thread_callback_t start, void *arg, void *fs)
{
	thread_t* new_thread = malloc(sizeof(thread_t));
	
	if(!new_thread)
		return NULL;
	
	memset(new_thread, 0 ,sizeof(thread_t));

	new_thread->id = curr_id++;
	posix_memalign((void**) &new_thread->fpu_area, FPU_AREA_ALIGNMENT, FPU_AREA_SIZE);
	if(!new_thread->fpu_area)
	{
		free(new_thread->fpu_area);
		free(new_thread);
		return NULL;
	}
	memset(new_thread->fpu_area, 0, FPU_AREA_SIZE);
	setup_fpu_area(new_thread->fpu_area);

	new_thread->kernel_stack = (uintptr_t*)vmm_allocate_virt_address(VM_KERNEL, 4, VMM_TYPE_STACK, VMM_WRITE | VMM_NOEXEC, 0);
	if(!new_thread->kernel_stack)
	{
		free(new_thread->fpu_area);
		free(new_thread);
		return NULL;
	}
	if(!vmm_map_range(new_thread->kernel_stack, 4, VM_WRITE | VM_GLOBAL | VM_NOEXEC))
	{
		free(new_thread->fpu_area);
		free(new_thread);
		return NULL;
	}

	new_thread->kernel_stack = (void*)((char*) new_thread->kernel_stack + 0x4000);
	new_thread->kernel_stack_top = new_thread->kernel_stack;

	new_thread->owner = get_current_process();

	uint64_t *stack = new_thread->kernel_stack;
	uint64_t ds = 0x33, cs = 0x2b, rflags = regs->rflags;

	new_thread->rip = start;
	*--stack = ds; //SS
	*--stack = regs->rsp; //RSP
	*--stack = rflags; // RFLAGS
	*--stack = cs; //CS
	*--stack = (uint64_t) start; //RIP
	*--stack = regs->rax; // RAX
	*--stack = regs->rbx; // RBX
	*--stack = regs->rcx; // RCX
	*--stack = regs->rdx; // RDX
	*--stack = (uint64_t) arg; // RDI
	*--stack = regs->rsi; // RSI
	*--stack = regs->rbp; // RBP
	*--stack = regs->r15; // R15
	*--stack = regs->r14; // R14
	*--stack = regs->r13; // R13
	*--stack = regs->r12; // R12
	*--stack = regs->r11; // R11
	*--stack = regs->r10; // R10
	*--stack = regs->r9; // R9
	*--stack = regs->r8; // R8
	*--stack = ds; // DS
	new_thread->kernel_stack = stack;
	new_thread->fs = fs;

	return new_thread;
}
