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
#include <onyx/vm.h>
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
#include <onyx/syscall.h>
#include <onyx/percpu.h>

#include <onyx/x86/segments.h>
#include <onyx/x86/msr.h>
#include <onyx/x86/vm_layout.h>

#include <sys/time.h>

/* Creates a thread for the scheduler to switch to
   Expects a callback for the code(RIP) and some flags
*/
atomic_int curr_id = 1;

/* FIXME: All of this code is garbage and is repeating itself. Fix. */

thread_t* task_switching_create_context(thread_callback_t callback, uint32_t flags, void* args)
{
	thread_t* new_thread = malloc(sizeof(thread_t));
	
	if(!new_thread)
		return NULL;
	
	memset(new_thread, 0, sizeof(thread_t));

	new_thread->entry = callback;
	new_thread->flags = flags;
	new_thread->id = curr_id++;
	new_thread->refcount = 1;

	signal_context_init(new_thread);

	if(!(flags & THREAD_KERNEL))
	{
		posix_memalign((void**) &new_thread->fpu_area, FPU_AREA_ALIGNMENT, FPU_AREA_SIZE);
		if(!new_thread->fpu_area)
		{
			free(new_thread);
			return NULL;
		}

		memset(new_thread->fpu_area, 0, FPU_AREA_SIZE);
		setup_fpu_area(new_thread->fpu_area);
		new_thread->addr_limit = VM_USER_ADDR_LIMIT;
	}
	else
	{
		new_thread->addr_limit = VM_KERNEL_ADDR_LIMIT;
	}

	// If the thread is user mode, create a user stack
	if(!(flags & THREAD_KERNEL))
	{
		new_thread->user_stack = vm_mmap(NULL, 256 << PAGE_SHIFT, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, NULL, 0);
		if(!new_thread->user_stack)
		{
			free(new_thread->fpu_area);
			free(new_thread);
			return NULL;
		}
	}

	new_thread->kernel_stack = get_pages(VM_KERNEL, VM_TYPE_STACK, 4, VM_WRITE | VM_NOEXEC, 0);

	if(!new_thread->kernel_stack)
	{
		vm_munmap(get_current_address_space(),
			  new_thread->user_stack,
			  256 << PAGE_SHIFT);
		free(new_thread->fpu_area);
		free(new_thread);
		return NULL;
	}

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
	if(!(flags & THREAD_KERNEL))
		original_stack = (uintptr_t) new_thread->user_stack;

	uint64_t ds = KERNEL_DS, cs = KERNEL_CS, rf = 0x202;
	if(!(flags & THREAD_KERNEL))
		ds = USER_DS, cs = USER_CS, rf = 0x202;

	*--stack = ds; //SS
	*--stack = original_stack; //RSP
	*--stack = rf; // RFLAGS
	*--stack = cs; //CS
	*--stack = (uint64_t) callback; //RIP
	stack -= 2;
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

thread_t* task_switching_create_main_progcontext(thread_callback_t callback,
	uint32_t flags, int argc, char **argv, char **envp)
{
	thread_t* new_thread = malloc(sizeof(thread_t));
	
	if(!new_thread)
		return NULL;
	
	memset(new_thread, 0, sizeof(thread_t));

	new_thread->entry = callback;
	new_thread->flags = flags;
	new_thread->id = curr_id++;
	new_thread->refcount = 1;

	signal_context_init(new_thread);

	new_thread->fpu_area = aligned_alloc(FPU_AREA_ALIGNMENT, FPU_AREA_SIZE);
	if(!new_thread->fpu_area)
	{
		free(new_thread);
		return NULL;
	}

	memset(new_thread->fpu_area, 0, FPU_AREA_SIZE);

	setup_fpu_area(new_thread->fpu_area);
	if(!(flags & THREAD_KERNEL)) // If the thread is user mode, create a user stack
	{
		new_thread->user_stack = vm_mmap(NULL, 256 << PAGE_SHIFT, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, NULL, 0);
		if(!new_thread->user_stack)
		{
			free(new_thread->fpu_area);
			free(new_thread);
			return NULL;
		}

		new_thread->addr_limit = VM_USER_ADDR_LIMIT;
	}
	else
		new_thread->addr_limit = VM_KERNEL_ADDR_LIMIT;
	
	new_thread->kernel_stack = (uintptr_t*) get_pages(VM_KERNEL, VM_TYPE_STACK, 4,
		VM_WRITE | VM_NOEXEC , 0);
	
	if(!new_thread->kernel_stack)
	{
		return NULL;
	}

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
		original_stack = (uintptr_t) new_thread->user_stack;
	
	uint64_t ds = 0x10, cs = 0x08, rf = 0x202;
	if(!(flags & 1))
		ds = 0x33, cs = 0x2b, rf = 0x202;
	
	*--stack = ds; //SS
	*--stack = original_stack; //RSP
	*--stack = rf; // RFLAGS
	*--stack = cs; //CS
	*--stack = (uint64_t) callback; //RIP
	stack -= 2;
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

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

int sys_arch_prctl(int code, unsigned long *addr)
{
	struct thread *current = get_current_thread();
	switch(code)
	{
		case ARCH_SET_FS:
		{
			current->fs = (void*) addr;
			wrmsr(FS_BASE_MSR, (uintptr_t) current->fs);
			break;
		}
		case ARCH_GET_FS:
		{
			if(copy_to_user(addr, &current->fs, sizeof(unsigned long)) < 0)
				return -EFAULT;
			break;
		}
		case ARCH_SET_GS:
		{
			current->gs = (void*) addr;
			wrmsr(KERNEL_GS_BASE, (uintptr_t) current->gs);
			break;
		}
		case ARCH_GET_GS:
		{
			if(copy_to_user(addr, current->gs, sizeof(unsigned long)) < 0)
				return -EFAULT;
			break;
		}
	}

	return 0;
}

void thread_finish_destruction(void *___thread)
{
	thread_t *thread = ___thread;
	/* Destroy the kernel stack */
	vfree((void*) ((uintptr_t)thread->kernel_stack_top - 0x4000), 4);
	
	/* Free the fpu area */
	free(thread->fpu_area);

	thread_remove_from_list(thread);
	/* Free the thread */
	free(thread);
}

thread_t *sched_spawn_thread(registers_t *regs, thread_callback_t start, void *arg, void *fs)
{
	thread_t* new_thread = zalloc(sizeof(thread_t));
	
	if(!new_thread)
		return NULL;

	new_thread->id = curr_id++;
	
	posix_memalign((void**) &new_thread->fpu_area, FPU_AREA_ALIGNMENT, FPU_AREA_SIZE);
	
	if(!new_thread->fpu_area)
	{
		free(new_thread);
		return NULL;
	}

	new_thread->refcount = 1;

	signal_context_init(new_thread);

	new_thread->addr_limit = VM_USER_ADDR_LIMIT;
	
	memset(new_thread->fpu_area, 0, FPU_AREA_SIZE);
	
	setup_fpu_area(new_thread->fpu_area);

	new_thread->kernel_stack = vmalloc(4, VM_TYPE_STACK, VM_WRITE | VM_NOEXEC);

	if(!new_thread->kernel_stack)
	{
		free(new_thread->fpu_area);
		free(new_thread);
		return NULL;
	}

	new_thread->kernel_stack = (void*)((char*) new_thread->kernel_stack + 0x4000);
	new_thread->kernel_stack_top = new_thread->kernel_stack;

	new_thread->owner = get_current_process();

	uint64_t *stack = new_thread->kernel_stack;
	uint64_t ds = USER_DS, cs = USER_CS, rflags = regs->rflags;

	new_thread->entry = start;
	*--stack = ds; //SS
	*--stack = regs->rsp; //RSP
	*--stack = rflags; // RFLAGS
	*--stack = cs; //CS
	*--stack = (uint64_t) start; //RIP
	stack -= 2;
	*--stack = regs->rax; // RAX
	*--stack = regs->rbx; // RBX
	*--stack = regs->rcx; // RCX
	*--stack = regs->rdx; // RDX
	*--stack = (uint64_t) arg; // RDI
	*--stack = regs->rsi; // RSI
	*--stack = regs->rbp; // RBP
	*--stack = regs->r8; // r8
	*--stack = regs->r9; // r9
	*--stack = regs->r10; // r10
	*--stack = regs->r11; // R11
	*--stack = regs->r12; // R12
	*--stack = regs->r13; // R13
	*--stack = regs->r14; // R14
	*--stack = regs->r15; // R15
	*--stack = ds; // DS

	new_thread->kernel_stack = stack;
	new_thread->fs = fs;

	thread_append_to_global_list(new_thread);

	new_thread->priority = SCHED_PRIO_NORMAL;

	return new_thread;
}

void arch_save_thread(struct thread *thread, void *stack)
{
	/* No need to save the fpu context if we're a kernel thread! */
	if(!(thread->flags & THREAD_KERNEL))
		save_fpu(thread->fpu_area);
}

PER_CPU_VAR_NOUNUSED(unsigned long kernel_stack) = 0;
PER_CPU_VAR_NOUNUSED(unsigned long scratch_rsp) = 0;

void arch_load_thread(struct thread *thread, unsigned int cpu)
{
	write_per_cpu(kernel_stack, thread->kernel_stack_top);
	/* Fill the TSS with a kernel stack */
	set_kernel_stack((uintptr_t) thread->kernel_stack_top);

	if(!(thread->flags & THREAD_KERNEL))
	{
		restore_fpu(thread->fpu_area);

		wrmsr(FS_BASE_MSR, (uint64_t) thread->fs);
		wrmsr(KERNEL_GS_BASE, (uint64_t) thread->gs);
	}
}

void arch_load_process(struct process *process, struct thread *thread,
                       unsigned int cpu)
{
	vm_load_arch_mmu(&process->address_space.arch_mmu);
}

unsigned long thread_get_addr_limit(void)
{
	struct thread *t = get_current_thread();
	assert(t->addr_limit != 0);
	return t->addr_limit;
}
