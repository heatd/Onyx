/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>

#include <onyx/scheduler.h>
#include <onyx/process.h>
#include <onyx/thread.h>

extern "C" {

struct thread *process_create_thread(struct process *proc, thread_callback_t callback, uint32_t flags)
{
	thread_t *thread = sched_create_thread(callback, flags, nullptr);

	if(!thread)
		return nullptr;

	spin_lock(&proc->thread_list_lock);

	list_add_tail(&thread->thread_list_head, &proc->thread_list);

	spin_unlock(&proc->thread_list_lock);

	thread->owner = proc;

	return thread;
}

struct thread *process_fork_thread(thread_t *src, struct process *dest, struct syscall_frame *ctx)
{
	registers_t regs;
	unsigned long rsp, rflags, ip;

	rsp = ctx->user_rsp;
	rflags = ctx->rflags;
	ip = ctx->rip;

	/* Setup the registers on the stack */
	regs.rax = 0;
	regs.rbx = ctx->rbx;
	regs.rcx = 0;
	regs.rdx = ctx->rdx;
	regs.rdi = ctx->rdi;
	regs.rsi = ctx->rsi;
	regs.rbp = ctx->rbp;
	regs.rsp = rsp;
	regs.rip = ip;
	regs.r8 = ctx->r8;
	regs.r9 = ctx->r9;
	regs.r10 = ctx->r10;
	regs.r11 = 0;
	regs.r12 = ctx->r12;
	regs.r13 = ctx->r13;
	regs.r14 = ctx->r14;
	regs.r15 = ctx->r15;
	regs.rflags = rflags;

	thread_t *thread = sched_spawn_thread(&regs, 0, src->fs);
	if(!thread)
		return nullptr;

	save_fpu(thread->fpu_area);

	thread->owner = dest;

	list_add_tail(&thread->thread_list_head, &dest->thread_list);
	return thread;
}

int process_alloc_stack(struct stack_info *info)
{
	void *ptr = vm_mmap(nullptr, info->length, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, nullptr, 0);
	if(!ptr)
		return -ENOMEM;
	info->base = ptr;
	info->top = reinterpret_cast<void *>((unsigned long) ptr + info->length);

	return 0;
}

struct thread *process_create_main_thread(struct process *proc, thread_callback_t callback, void *sp,
                                     int argc, char **argv, char **envp)
{
	registers_t regs = {};
	regs.rsp = reinterpret_cast<unsigned long>(sp);
	regs.rdi = static_cast<unsigned long>(argc);
	regs.rsi = reinterpret_cast<unsigned long>(argv);
	regs.rdx = reinterpret_cast<unsigned long>(envp);
	regs.rip = reinterpret_cast<unsigned long>(callback);
	regs.rflags = default_rflags;

	auto t = sched_spawn_thread(&regs, 0, nullptr);
	if(!t)
		return nullptr;

	t->owner = proc;

	/* No need to lock here because the thread isn't even alive yet. */
	list_add_tail(&t->thread_list_head, &proc->thread_list);

	proc->nr_threads = 1;

	return t;
}

#define CLONE_FORK           (1 << 0)
#define CLONE_SPAWNTHREAD	 (1 << 1)
long valid_flags = CLONE_FORK | CLONE_SPAWNTHREAD;

int sys_clone(int (*fn)(void *), void *child_stack, int flags, void *arg, pid_t *ptid, void *tls)
{
	if(flags & ~valid_flags)
		return -EINVAL;
	if(flags & CLONE_FORK)
		return -EINVAL; /* TODO: Add CLONE_FORK */
	thread_callback_t start = (thread_callback_t) fn;

	registers_t regs = {};
	regs.rsp = (unsigned long) child_stack;
	regs.rflags = default_rflags;
	regs.rip = (unsigned long) start;
	regs.rdi = (unsigned long) arg;

	thread_t *thread = sched_spawn_thread(&regs, 0, tls);
	if(!thread)
		return -errno;

	if(copy_to_user(ptid, &thread->id, sizeof(pid_t)) < 0)
	{
		thread_destroy(thread);
		return -errno;
	}

	thread->ctid = ptid;

	process_add_thread(get_current_process(), thread);
	sched_start_thread(thread);

	return 0;
}

}