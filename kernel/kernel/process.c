/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <sys/resource.h>

#include <onyx/user.h>
#include <onyx/id.h>
#include <onyx/vdso.h>
#include <onyx/compiler.h>
#include <onyx/elf.h>
#include <onyx/process.h>
#include <onyx/task_switching.h>
#include <onyx/cpu.h>
#include <onyx/random.h>
#include <onyx/mutex.h>
#include <onyx/panic.h>
#include <onyx/binfmt.h>
#include <onyx/worker.h>
#include <onyx/page.h>
#include <onyx/thread.h>
#include <onyx/file.h>
#include <onyx/slab.h>
#include <onyx/proc_event.h>

#include <pthread_kernel.h>

#define __WCONSTRUCT(nature, exitcode, signal) \
        (((nature) & 0xFF) << 16 | \
         ((exitcode) & 0xFF) << 8 | \
         ((signal) & 0x7F) << 0)

extern PML4 *current_pml4;
struct ids *process_ids = NULL;
struct process *first_process = NULL;
volatile struct process *current_process = NULL;
static struct spinlock process_creation_lock;
slab_cache_t *process_cache = NULL;
void process_destroy(thread_t *);

int copy_file_descriptors(struct process *process, ioctx_t *ctx)
{
	process->ctx.file_desc = malloc(ctx->file_desc_entries * sizeof(void*));
	process->ctx.file_desc_entries = ctx->file_desc_entries;
	if(!process->ctx.file_desc)
		return -1;
	for(int i = 0; i < process->ctx.file_desc_entries; i++)
	{
		process->ctx.file_desc[i] = ctx->file_desc[i];
		if(ctx->file_desc[i])
			ctx->file_desc[i]->refcount++;
	}
	return 0;
}

int allocate_file_descriptor_table(struct process *process)
{
	process->ctx.file_desc = malloc(UINT8_MAX * sizeof(void*));
	if(!process->ctx.file_desc)
	{
		return -1;
	}
	memset(process->ctx.file_desc, 0, UINT8_MAX * sizeof(void*));
	process->ctx.file_desc_entries = UINT8_MAX;
	return 0;
}

struct process *process_create(const char *cmd_line, ioctx_t *ctx, struct process *parent)
{
	if(unlikely(!process_cache))
	{
		process_cache = slab_create("struct process", sizeof(struct process), 16, 0, 0, 0);
		if(!process_cache)
			panic("Could not create the process slab cache\n");
	}
	
	if(unlikely(!process_ids))
	{
		process_ids = idm_add("pid", 1, UINTMAX_MAX);
		assert(process_ids != NULL);
	}

	struct process *proc = slab_allocate(process_cache);
	if(!proc)
		return errno = ENOMEM, NULL;
	memset(proc, 0, sizeof(struct process));
	spin_lock(&process_creation_lock);
	/* TODO: idm_get_id doesn't wrap? POSIX COMPLIANCE */
	proc->pid = idm_get_id(process_ids);
	assert(proc->pid != (pid_t) -1);
	proc->cmd_line = strdup(cmd_line);
	if(ctx)
	{
		if(copy_file_descriptors(proc, ctx) < 0)
		{
			slab_free(process_cache, proc);
			spin_unlock(&process_creation_lock);
			return NULL;
		}
		proc->ctx.cwd = ctx->cwd;
		proc->ctx.name = ctx->name;
	}
	else
	{
		if(allocate_file_descriptor_table(proc) < 0)
		{
			slab_free(process_cache, proc);
			spin_unlock(&process_creation_lock);
			return NULL;
		}
	}
	if(parent)
	{
		/* Inherit the parent process' properties */
		proc->personality = parent->personality;
		proc->vdso = parent->vdso;
		proc->uid = parent->uid;
		proc->gid = parent->gid;
		proc->address_space.brk = parent->address_space.brk;
		/* Inherit the signal handlers and signal mask */
		memcpy(&proc->sigtable, &parent->sigtable, sizeof(struct sigaction) * _NSIG);
		memcpy(&proc->sigmask, &parent->sigmask, sizeof(sigset_t));
	}

	proc->address_space.process = proc;
	if(parent)
		proc->parent = parent;
	if(!first_process)
		first_process = proc;
	else
	{
		struct process *it = (struct process*) get_current_process();
		while(it->next) it = it->next;
		it->next = proc;
	}
	spin_unlock(&process_creation_lock);
	return proc;
}

void process_create_thread(struct process *proc, thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp)
{
	thread_t *thread = NULL;
	if(!argv)
		thread = sched_create_thread(callback, flags, NULL);
	else
		thread = sched_create_main_thread(callback, flags, argc, argv, envp);
	int is_set = 0;
	for(int i = 0; i < THREADS_PER_PROCESS; i++)
	{
		if(proc->threads[i] == NULL)
		{
			proc->threads[i] = thread;
			thread->owner = proc;
			is_set = 1;
		}
	}
	if(!is_set)
		thread_destroy(thread);
}

int process_fork_thread(thread_t *src, struct process *dest, syscall_ctx_t *ctx)
{
	registers_t 	regs;
	uintptr_t 	rsp;
	uintptr_t 	rflags;
	uintptr_t 	ip;
	
	/* TODO: Move this to arch/x86_64/process.c */
	rsp = (uintptr_t) src->user_stack;
	rflags = ctx->r11;
	ip = ctx->rcx;

	/* Setup the registers on the stack */
	regs.rax = 0;
	regs.rbx = ctx->rbx;
	regs.rcx = ctx->rcx;
	regs.rdx = ctx->rdx;
	regs.rdi = ctx->rdi;
	regs.rsi = ctx->rsi;
	regs.rbp = ctx->rbp;
	regs.rsp = rsp;
	regs.rip = ip;
	regs.r8 = ctx->r8;
	regs.r9 = ctx->r9;
	regs.r10 = ctx->r10;
	regs.r11 = ctx->r11;
	regs.r12 = ctx->r12;
	regs.r13 = ctx->r13;
	regs.r14 = ctx->r14;
	regs.r15 = ctx->r15;
	regs.rflags = rflags;
	thread_t *thread = sched_spawn_thread(&regs, (thread_callback_t) regs.rcx,
					      (void*) regs.rdi, src->fs);
	if(!thread)
		return -1;

	/* Don't forget saving the FPU registers! */
	save_fpu(thread->fpu_area);

	dest->threads[0] = thread;
	thread->owner = dest;
	return 0;
}

struct process *get_process_from_pid(pid_t pid)
{
	struct process *p = first_process;
	for(;p;p = p->next)
	{
		if(p->pid == pid)
			return p;
	}
	return NULL;
}

char **process_copy_envarg(char **envarg, _Bool to_kernel, int *count)
{
	/* Copy the envp/argv to another buffer */
	/* Each buffer takes up argc * sizeof pointer + string_size + one extra pointer(to NULL terminate) */
	size_t nr_args = 0;
	size_t string_size = 0;
	char **b = envarg;
	while(*b)
	{
		string_size += strlen(*b) + 1;
		nr_args++;
		b++;
	}
	size_t buffer_size = (nr_args + 1) * sizeof(void*) + string_size;
	char *new;
	if(to_kernel)
	{
		new = zalloc(buffer_size);
		if(!new)
			return NULL;
	}
	else
	{
		new = get_user_pages(VM_TYPE_SHARED,
			vmm_align_size_to_pages(buffer_size), VM_WRITE | VM_NOEXEC | VM_USER);
		if(!new)
			return NULL;
	}

	char *strings = (char*) new + (nr_args + 1) * sizeof(void*);
	char *it = strings;
	/* Actually copy the buffer */
	for(size_t i = 0; i < nr_args; i++)
	{
		strcpy(it, envarg[i]);
		it += strlen(envarg[i]) + 1;
	}
	char **new_args = (char**) new;
	for(size_t i = 0; i < nr_args; i++)
	{
		new_args[i] = (char*) strings;
		strings += strlen(new_args[i]) + 1;
	}
	if(count)
		*count = nr_args;
	return new_args;
}

void *process_setup_auxv(void *buffer, struct process *process)
{
	process->vdso = map_vdso();
	/* Setup the auxv at the stack bottom */
	Elf64_auxv_t *auxv = (Elf64_auxv_t *) buffer;
	unsigned char *scratch_space = (unsigned char *) (auxv + 37);
	for(int i = 0; i < 38; i++)
	{
		if(i != 0)
			auxv[i].a_type = i;
		else
			auxv[i].a_type = 0xffff;
		if(i == 37)
			auxv[i].a_type = 0;
		switch(i)
		{
			case AT_PAGESZ:
				auxv[i].a_un.a_val = PAGE_SIZE;
				break;
			case AT_UID:
				auxv[i].a_un.a_val = process->uid;
				break;
			case AT_GID:
				auxv[i].a_un.a_val = process->gid;
				break;
			case AT_RANDOM:
				get_entropy((char*) scratch_space, 16);
				scratch_space += 16;
				break;
			case AT_BASE:
				auxv[i].a_un.a_val = (uintptr_t) process->image_base;
				break;
			case AT_PHENT:
				auxv[i].a_un.a_val = process->info.phent;
				break;
			case AT_PHNUM:
				auxv[i].a_un.a_val = process->info.phnum;
				break;
			case AT_PHDR:
				auxv[i].a_un.a_val = (uintptr_t) process->info.phdr;
				break;
			case AT_EXECFN:
				auxv[i].a_un.a_val = (uintptr_t) scratch_space;
				strcpy((char*) scratch_space, process->cmd_line);
				scratch_space += strlen((const char*) scratch_space) + 1;
				break;
			case AT_SYSINFO_EHDR:
				auxv[i].a_un.a_val = (uintptr_t) process->vdso;
				break;
		}
	}
	return auxv;
}

void process_setup_pthread(thread_t *thread, struct process *process)
{
	/* TODO: Do this portably */
	/* TODO: Return error codes and clean up */
	uintptr_t *fs = get_user_pages(VM_TYPE_REGULAR, 1, VM_WRITE | VM_NOEXEC | VM_USER);
	vmm_map_range(fs, 1, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	thread->fs = (void*) fs;
	__pthread_t *p = (__pthread_t*) fs;
	p->self = (__pthread_t*) fs;
	p->tid = get_current_process()->threads[0]->id;
	p->pid = get_current_process()->pid;
}

/*
	return_from_execve(): Return from execve, while loading registers and zero'ing the others.
	Does not return!
*/ 
int return_from_execve(void *entry, int argc, char **argv, char **envp, void *auxv, void *stack);
/*
	execve(2): Executes a program with argv and envp, replacing the current process.
*/
int sys_execve(char *p, char *argv[], char *envp[])
{
	if(!vmm_is_mapped(argv))
		return errno =-EFAULT;
	if(!vmm_is_mapped(envp))
		return errno =-EFAULT;

	char *path = strcpy_from_user(p);
	if(!path)
		return -ENOMEM;
	struct process *current = get_current_process();

	/* Copy argv and envp to the kernel space */
	int argc;
	char **karg = process_copy_envarg(argv, true, &argc);
	/* TODO: Abort process construction */
	if(!karg)
	{
		free(path);
		return -ENOMEM;
	}
	char **kenv = process_copy_envarg(envp, true, NULL);
	if(!kenv)
	{
		free(karg);
		free(path);
		return -ENOMEM;
	}

	/* Open the file */
	struct inode *in = open_vfs(get_fs_root(), path);
	if (!in)
	{
		free(path);
		free(karg);
		free(kenv);
		return -ENOENT;
	}

	if(vm_clone_as(&current->address_space) < 0)
	{
		free(path);
		free(karg);
		free(kenv);
		close_vfs(in);
		return -1;
	}
	/* TODO: Check file permitions */
	/* Swap address spaces. Good thing we saved argv and envp before */
	current->address_space.brk = map_user(vmm_gen_brk_base(), 0x20000000, VM_TYPE_HEAP,
		VM_WRITE | VM_NOEXEC | VM_USER);
	current->address_space.mmap_base = vmm_gen_mmap_base();

	current->cmd_line = strdup(path);
	paging_load_cr3(current->address_space.cr3);
	
	/* Setup the binfmt args */
	uint8_t *file = malloc(100);
	if(!file)
	{
		free(karg);
		free(kenv);
		close_vfs(in);
		return -ENOMEM;
	}
	/* Read the file signature */
	read_vfs(0, 0, 100, file, in);
	struct binfmt_args args = {0};
	args.file_signature = file;
	args.filename = current->cmd_line;
	args.argv = karg;
	args.envp = kenv;
	args.file = in;

	/* Load the actual binary */
	void *entry = load_binary(&args);
	if(!entry)
	{
		free(karg);
		free(kenv);
		free(file);
		close_vfs(in);
		return -errno;
	}

	free(file);

	/* Copy argv and envp to user space memory */
	char **uargv = process_copy_envarg(karg, false, NULL);
	if(!uargv)
		return -errno;
	char **uenv = process_copy_envarg(kenv, false, NULL);
	if(!uenv)
		return -errno;
	/* Free karg and kenv, we don't need them anymore  */
	free(karg);
	free(kenv);

	/* Close O_CLOEXEC files */
	file_do_cloexec(&get_current_process()->ctx);

	void *user_stack = get_user_pages(VM_TYPE_SHARED, 256, VM_WRITE | VM_NOEXEC | VM_USER);
	void *auxv = NULL;
	if(!user_stack)
		return -1;

	/* Setup auxv */
	auxv = process_setup_auxv(user_stack, current);
	user_stack = (char*) user_stack + 256 * PAGE_SIZE;
	get_current_thread()->user_stack_bottom = user_stack;

	free(path);
	return return_from_execve(entry, argc, uargv, uenv, auxv, user_stack);
}

pid_t sys_getppid()
{
	if(get_current_process()->parent)
		return get_current_process()->parent->pid;
	else
		return -1;
}

pid_t sys_wait4(pid_t pid, int *wstatus, int options, struct rusage *usage)
{
	struct process *it = (struct process*) get_current_process();
	struct process *current = get_current_process();
	bool found_child = 0;
	bool looking_for_any_children = false;


	if(pid < 0)
	{
		looking_for_any_children = true;
	}

	while(it)
	{
		if(it->parent == current)
		{
			if(it->pid == pid || pid < 0)
				found_child = 1;
		}
		it = it->next;
	}

	if(!found_child)
	{
		return -ECHILD;
	}

	it = first_process;
	while(true)
	{
		if(signal_is_pending())
			return -EINTR;

		spin_lock(&process_creation_lock);
		for(struct process *p = first_process; p != NULL; p = p->next)
		{
			if(p->parent == current && p->has_exited == 1 &&
			 (looking_for_any_children == true || p->pid == pid))
			{
				copy_to_user(wstatus, &p->exit_code, sizeof(int));
				
				p->parent = NULL;
				spin_unlock(&process_creation_lock);
				/* TODO: Destroy */
				return p->pid;
			}
		}

		spin_unlock(&process_creation_lock);
		sem_wait(&current->wait_sem);
	}

	return 0;
}

pid_t sys_fork(syscall_ctx_t *ctx)
{
	struct process 	*proc;
	struct process 	*child;
	thread_t 	*to_be_forked;

	proc = (struct process*) get_current_process();
	to_be_forked = proc->threads[0];	
	/* Create a new process */
	child = process_create(proc->cmd_line, &proc->ctx, proc); /* Create a process with the current
			  			  * process's info */
	if(!child)
		return -ENOMEM;

	/* Fork the vmm data and the address space */
	if(vm_fork_as(&child->address_space) < 0)
		return -ENOMEM;

	/* Fork and create the new thread */
	process_fork_thread(to_be_forked, child, ctx);

	sched_start_thread(child->threads[0]);

	// Return the pid to the caller
	return child->pid;
}

int make_wait4_wstatus(int signum, bool core_dumped, int exit_code)
{
	int wstatus = 0;

	wstatus = ((int) core_dumped << 7);

	if(signum == 0)
	{
		wstatus = exit_code << 8;
		return wstatus;
	}
	else
	{
		switch(signum)
		{
			case SIGCONT:
			case SIGSTOP:
				wstatus |= (0177 << 0);
				break;
			default:
				wstatus |= (signum << 0); 
		}

		wstatus |= (signum << 8);

		return wstatus;

	}
}

void process_exit_from_signal(int signum)
{
	struct process *current = get_current_process();

	current->has_exited = 1;
	current->exit_code = make_wait4_wstatus(signum, false, 0);
	sem_signal(&current->parent->wait_sem);
	
	/* TODO: Support multi-threaded processes */
	thread_t *current_thread = get_current_thread();


	process_destroy(current_thread);

	sched_yield();
}

void sys_exit(int status)
{
	struct process *current = get_current_process();
	if(current->pid == 1)
	{
		printk("Panic: %s returned!\n", get_current_process()->cmd_line);
		ENABLE_INTERRUPTS();
		for(;;);
	}
	current->has_exited = 1;
	current->exit_code = make_wait4_wstatus(0, false, status);
	sem_signal(&current->parent->wait_sem);

	/* TODO: Support multi-threaded processes */
	thread_t *current_thread = get_current_thread();

	process_destroy(current_thread);

	sched_yield();
}

uint64_t sys_getpid()
{
	return get_current_process()->pid;
}

int sys_personality(unsigned long val)
{
	// TODO: Use this syscall for something. This might be potentially very useful
	get_current_process()->personality = val;
	return 0;
}

int sys_setuid(uid_t uid)
{
	get_current_process()->uid = uid;
	return 0;
}

int sys_setgid(gid_t gid)
{
	get_current_process()->gid = gid;
	return 0;
}

uid_t sys_getuid(void)
{
	return get_current_process()->uid;
}

gid_t sys_getgid(void)
{
	return get_current_process()->gid;
}

void process_destroy_aspace(void)
{
	struct process *current = get_current_process();

	vmm_destroy_addr_space(current->address_space.tree);
	current->address_space.tree = NULL;
}

void process_destroy_file_descriptors(struct process *process)
{
	ioctx_t *ctx = &process->ctx;
	file_desc_t **table = ctx->file_desc;
	mutex_lock(&ctx->fdlock);

	for(int i = 0; i < ctx->file_desc_entries; i++)
	{
		/* TODO: Handle vfsnode freeing */
		if(!table[i])
			continue;
		table[i]->refcount--;
		if(!table[i]->refcount)
		{
			free(table[i]);
		}
	}
	free(table);
	ctx->file_desc = NULL;
	ctx->file_desc_entries = 0;
}

void process_obliterate(void *proc)
{
	struct process *process = proc;
	__free_page(process->address_space.cr3);
}

void process_destroy(thread_t *current_thread)
{
	struct process *current = get_current_process();

	/* Firstly, destroy the address space */
	process_destroy_aspace();

	process_destroy_file_descriptors(current);

	free(current->cmd_line);

	for(struct proc_event_sub *s = current->sub_queue; s; s = s->next)
	{
		s->valid_sub = false;
	}

	/* Destroy everything that can be destroyed now */
	thread_destroy(current_thread);

	/* Schedule the obliteration of the process */
	struct work_request req;
	req.func = process_obliterate;
	req.param = current;
	worker_schedule(&req, WORKER_PRIO_NORMAL);
}

int process_attach(struct process *tracer, struct process *tracee)
{
	/* You can't attach to yourself */
	if(tracer == tracee)
		return errno = ESRCH, -1;
	/* TODO: Enforce process permitions */
	if(!tracer->tracees.ptr)
	{
		tracer->tracees.ptr = tracee;
	}
	else
	{
		if(list_add(&tracer->tracees, tracee) < 0)
			return errno = ENOMEM, -1;
	}
	return 0;
}

/* Finds a pid that tracer is tracing */
struct process *process_find_tracee(struct process *tracer, pid_t pid)
{
	struct list_head *list = &tracer->tracees;
	while(list && list->ptr)
	{
		struct process *tracee = list->ptr;
		if(tracee->pid == pid)
			return tracee;
		list = list->next;
	}
	return NULL;
}

void process_add_thread(struct process *process, thread_t *thread)
{
	for(int i = 0; i < THREADS_PER_PROCESS; i++)
	{
		if(!process->threads[i])
		{
			process->threads[i] = thread;
			return;
		}
	}
}

#define CLONE_FORK		(1 << 0)
#define CLONE_SPAWNTHREAD	(1 << 1)
long valid_flags = CLONE_FORK | CLONE_SPAWNTHREAD;

int sys_clone(int (*fn)(void *), void *child_stack, int flags, void *arg, pid_t *ptid, void *tls)
{
	if(flags & ~valid_flags)
		return -EINVAL;
	if(!vmm_is_mapped(fn))
		return -EINVAL;
	if(flags & CLONE_FORK)
		return -EINVAL; /* TODO: Add CLONE_FORK */
	thread_callback_t start = (thread_callback_t) fn;

	registers_t regs;
	memset(&regs, 0, sizeof(registers_t));
	regs.rsp = (uint64_t) child_stack;
	thread_t *thread = sched_spawn_thread(&regs, start, arg, tls);
	if(!thread)
		return -errno;
	if(vmm_check_pointer(ptid, sizeof(pid_t)) > 0)
		*ptid = thread->id;
	process_add_thread(get_current_process(), thread);
	return 0;
}

void sys_exit_thread(int value)
{
	thread_t *thr = get_current_thread();
	/* Okay, so the libc called us. That means we can start destroying the thread */
	/* NOTE: I'm not really sure if musl destroyed the user stack and fs, and if we should anything to free them */
	/* Destroy the thread */
	thread_destroy(thr);
	/* aaaaand we'll never return back to user-space, so just hang on */
	while(1);
}

void process_increment_stats(bool is_kernel)
{
	struct process *process = get_current_process();
	/* We're not in a process, return! */
	if(!process)
		return;
	if(is_kernel)
		process->system_time++;
	else
		process->user_time++;
}

void process_continue(struct process *p)
{
	if(p->threads[0])
		thread_set_state(p->threads[0], THREAD_RUNNABLE);
}

void process_stop(struct process *p)
{
	if(p->threads[0])
		thread_set_state(p->threads[0], THREAD_BLOCKED);
	if(p == get_current_process())
		sched_yield();
}
