/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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
#include <kernel/worker.h>
#include <kernel/cpu.h>

extern PML4 *current_pml4;
static thread_t *run_queue = NULL;
static thread_t *idle_thread = NULL; 
static spinlock_t run_queue_lock;
static _Bool is_initialized = false;
thread_t *sched_find_runnable(void)
{
	thread_t *t = get_current_thread()->next;
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
bool sched_is_preemption_disabled(void)
{
	struct processor *p = get_processor_data();
	if(!p)
		return false;
	return p->preemption_disabled;
}
void sched_change_preemption_state(bool disable)
{
	struct processor *p = get_processor_data();
	if(!p)
		return;
	p->preemption_disabled = disable;
}
void* sched_switch_thread(void* last_stack)
{
	if(is_initialized == 0 || sched_is_preemption_disabled())
	{
		return last_stack;
	}
	struct processor *p = get_processor_data();
	thread_t *current_thread = p->current_thread;

	if(unlikely(!current_thread))
	{
		current_thread = run_queue;
		set_kernel_stack((uintptr_t) current_thread->kernel_stack_top);
		p->kernel_stack = current_thread->kernel_stack_top;
		p->current_thread = current_thread;
		return current_thread->kernel_stack;
	}
	current_thread->kernel_stack = (uintptr_t*) last_stack;
	if(likely(get_current_process()))
	{
		get_current_process()->tree = vmm_get_tree();
		get_current_process()->errno = errno;
	}

	/* Save the FPU state */
	save_fpu(current_thread->fpu_area);

	current_thread = sched_find_runnable();
	p->kernel_stack = current_thread->kernel_stack_top;
	/* Fill the TSS with a kernel stack*/
	set_kernel_stack((uintptr_t)current_thread->kernel_stack_top);

	/* Restore the FPU state */
	restore_fpu(current_thread->fpu_area);
	current_process = current_thread->owner;
	if(get_current_process())
	{
		vmm_set_tree(get_current_process()->tree);
		
		if (current_pml4 != get_current_process()->cr3)
		{
			paging_load_cr3(get_current_process()->cr3);
		}
		errno = get_current_process()->errno;
		wrmsr(FS_BASE_MSR, (uintptr_t) current_thread->fs & 0xFFFFFFFF, (uintptr_t)current_thread->fs >> 32);
		wrmsr(KERNEL_GS_BASE, (uintptr_t) current_thread->gs & 0xFFFFFFFF, (uintptr_t) current_thread->gs >> 32);
	}

	p->current_thread = current_thread;
	return current_thread->kernel_stack;
}
thread_t *get_current_thread()
{
	struct processor *p = get_processor_data();
	if(unlikely(!p))
		return NULL;
	return (thread_t*) p->current_thread;
}
void sched_idle()
{
	/* This function will not do work at all, just idle using hlt */
	for(;;)
	{
		__asm__ __volatile__("hlt");
	}
}
void thread_add(thread_t *add)
{
	acquire_spinlock(&run_queue_lock);
	thread_t *it = run_queue;
	while(it->next)
	{
		it = it->next;
	}
	it->next = add;
	release_spinlock(&run_queue_lock);
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
	__asm__ __volatile__("int $0x81");
}
void sched_sleep(unsigned long ms)
{
	get_current_thread()->timestamp = get_tick_count();
	get_current_thread()->sleeping_for = ms;
	get_current_thread()->status = THREAD_SLEEPING;
	sched_yield();
}
void sched_remove_thread(thread_t *thread)
{	
	thread_t *it = run_queue;
	for(; it->next; it = it->next)
	{
		if(it->next == thread)
		{
			it->next = thread->next;
			return;
		}
	}
}
void set_current_thread(thread_t *t)
{
	get_processor_data()->current_thread = t;
}
pid_t sys_set_tid_address(pid_t *tidptr)
{
	return get_current_thread()->id;
}
int sys_nanosleep(const struct timespec *req, struct timespec *rem)
{
	if(vmm_check_pointer((void*) req, sizeof(struct timespec)) < 0)
		return -EFAULT;
	time_t ticks = req->tv_sec * 1000;
	if(req->tv_nsec)
	{
		if(req->tv_nsec < 500)
			ticks++;
	}
	sched_sleep(ticks);
	return 0;
}
extern void thread_finish_destruction(void*);
void thread_destroy(thread_t *thread)
{
	/* This function should destroy everything that we can destroy right now.
	 * We can't destroy things like the kernel stack or the FPU area, because we'll eventually 
	 * need to context switch out of here,
	 * or you know, we're actually using the kernel stack right now!
	*/
	
	/* Remove the thread from the queue */
	sched_remove_thread(thread);

	/* Destroy the user stack */
	if(thread->user_stack_bottom) vmm_destroy_mappings(thread->user_stack_bottom, 256);
	
	/* Schedule further thread destruction */
	struct work_request req;
	req.func = thread_finish_destruction;
	req.param = thread;
	worker_schedule(&req, WORKER_PRIO_NORMAL);
}
void thread_set_state(thread_t *thread, int state)
{
	thread->status = state;
}
void thread_wake_up(thread_t *thread)
{
	thread->status = THREAD_RUNNABLE;
}
void sched_sleep_until_wake(void)
{
	get_current_thread()->status = THREAD_SLEEPING;
	sched_yield();
}
void thread_wake_up_ftx(thread_t *thread)
{
	thread_wake_up(thread);
	thread->woken_up_by_futex = true;
}
void thread_reset_futex_state(thread_t *thread)
{
	thread->woken_up_by_futex = false;
}
