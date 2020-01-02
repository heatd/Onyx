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
#include <onyx/syscall.h>
#include <onyx/futex.h>
#include <onyx/utils.h>

#include <pthread_kernel.h>

#define __WCONSTRUCT(nature, exitcode, signal) \
        (((nature) & 0xFF) << 16 | \
         ((exitcode) & 0xFF) << 8 | \
         ((signal) & 0x7F) << 0)

extern PML *current_pml4;
struct ids *process_ids = NULL;

struct process *first_process = NULL;
static struct process *process_tail = NULL;
static struct spinlock process_list_lock;
volatile struct process *current_process = NULL;
slab_cache_t *process_cache = NULL;

void process_destroy(thread_t *);
void process_end(struct process *process);

int copy_file_descriptors(struct process *process, ioctx_t *ctx)
{
	mutex_lock(&ctx->fdlock);

	process->ctx.file_desc = malloc(ctx->file_desc_entries * sizeof(void*));
	process->ctx.file_desc_entries = ctx->file_desc_entries;
	if(!process->ctx.file_desc)
	{
		mutex_unlock(&ctx->fdlock);
		return -1;
	}

	for(int i = 0; i < process->ctx.file_desc_entries; i++)
	{
		process->ctx.file_desc[i] = ctx->file_desc[i];
		if(ctx->file_desc[i])
			fd_get(ctx->file_desc[i]);
	}

	mutex_unlock(&ctx->fdlock);
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

void process_append_children(struct process *parent, struct process *children)
{
	spin_lock(&parent->children_lock);

	struct process **pp = &parent->children;

	while(*pp)
		pp = &(*pp)->next_sibbling;
	
	*pp = children;

	children->prev_sibbling = container_of(pp, struct process, next_sibbling);

	spin_unlock(&parent->children_lock);
}

void process_append_to_global_list(struct process *p)
{
	spin_lock(&process_list_lock);
	
	if(process_tail)
	{
		process_tail->next = p;
		process_tail = p;
	}
	else
	{
		first_process = process_tail = p;
	}

	p->next = NULL;

	spin_unlock(&process_list_lock);
}

struct process *process_create(const char *cmd_line, ioctx_t *ctx, struct process *parent)
{
	#if 0
	if(unlikely(!process_cache))
	{
		process_cache = slab_create("struct process", sizeof(struct process), 16, 0, 0, 0);
		if(!process_cache)
			panic("Could not create the process slab cache\n");
	}
	#endif

	if(unlikely(!process_ids))
	{
		process_ids = idm_add("pid", 1, UINTMAX_MAX);
		assert(process_ids != NULL);
	}

	struct process *proc = malloc(sizeof(struct process));
	if(!proc)
		return errno = ENOMEM, NULL;
	memset(proc, 0, sizeof(struct process));
	
	/* TODO: idm_get_id doesn't wrap? POSIX COMPLIANCE */
	proc->pid = idm_get_id(process_ids);
	assert(proc->pid != (pid_t) -1);
	proc->cmd_line = strdup(cmd_line);

	if(!proc->cmd_line)
	{
		free(proc);
		return NULL;
	}

	if(ctx)
	{
		object_ref(&ctx->cwd->i_object);

		proc->ctx.cwd = ctx->cwd;
		proc->ctx.name = strdup(ctx->name);

		if(!proc->ctx.name)
		{
			object_unref(&ctx->cwd->i_object);
			free(proc->cmd_line);
			free(proc);
			return NULL;
		}
		
		if(copy_file_descriptors(proc, ctx) < 0)
		{
			free((void *) proc->ctx.name);
			object_unref(&ctx->cwd->i_object);
			free(proc->cmd_line);
			free(proc);
			return NULL;
		}
	}
	else
	{
		if(allocate_file_descriptor_table(proc) < 0)
		{
			free(proc);
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
		/* Inherit the signal handlers of the process and the
		 * signal mask of the current thread
		*/
		memcpy(&proc->sigtable, &parent->sigtable, sizeof(struct sigaction) * _NSIG);
		/* Note that the signal mask is inherited at thread creation */
		
		/* Note that pending signals are zero'd, as per POSIX */

		process_append_children(parent, proc);

		proc->parent = parent;
	}

	proc->address_space.process = proc;

	process_append_to_global_list(proc);

	INIT_LIST_HEAD(&proc->thread_list);

	return proc;
}

struct thread *process_create_thread(struct process *proc, thread_callback_t callback,
	uint32_t flags, int argc, char **argv, char **envp)
{
	thread_t *thread = NULL;
	if(!argv)
		thread = sched_create_thread(callback, flags, NULL);
	else
		thread = sched_create_main_thread(callback, flags,
						  argc, argv, envp);

	if(!thread)
		return NULL;

	spin_lock(&proc->thread_list_lock);

	list_add_tail(&thread->thread_list_head, &proc->thread_list);

	spin_unlock(&proc->thread_list_lock);

	thread->owner = proc;

	return thread;
}

struct thread *process_fork_thread(thread_t *src, struct process *dest, struct syscall_frame *ctx)
{
	registers_t 	regs;
	uintptr_t 	rsp;
	uintptr_t 	rflags;
	uintptr_t 	ip;

	/* TODO: Move this to arch/x86_64/process.c */
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
	thread_t *thread = sched_spawn_thread(&regs, (thread_callback_t) regs.rip,
					      (void*) regs.rdi, src->fs);
	if(!thread)
		return NULL;

	save_fpu(thread->fpu_area);

	thread->owner = dest;

	list_add_tail(&thread->thread_list_head, &dest->thread_list);
	return thread;
}

struct process *get_process_from_pid(pid_t pid)
{

	spin_lock(&process_list_lock);

	for(struct process *p = first_process; p != NULL; p = p->next)
	{
		if(p->pid == pid)
		{
			spin_unlock(&process_list_lock);
			return p;
		}
	}

	spin_unlock(&process_list_lock);
	return NULL;
}

char **process_copy_envarg(char **envarg, bool to_kernel, int *count)
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
			vm_align_size_to_pages(buffer_size), VM_WRITE | VM_NOEXEC | VM_USER);
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

#if 0
void process_setup_pthread(thread_t *thread, struct process *process)
{
	/* TODO: Do this portably */
	/* TODO: Return error codes and clean up */
	uintptr_t *fs = get_user_pages(VM_TYPE_REGULAR, 1, VM_WRITE | VM_NOEXEC | VM_USER);
	thread->fs = (void*) fs;
	__pthread_t *p = (__pthread_t*) fs;
	p->self = (__pthread_t*) fs;
	p->tid = get_current_process()->threads[0]->id;
	p->pid = get_current_process()->pid;
}
#endif

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
	if(!vm_find_region(argv))
		return errno =-EFAULT;
	if(!vm_find_region(envp))
		return errno =-EFAULT;

	char *path = strcpy_from_user(p);
	if(!path)
		return -errno;
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
	if(vm_create_address_space(current, current->address_space.cr3) < 0)
	{
		/* TODO: Failure in sys_execve seems fragile. Test and fix. */
		free(path);
		free(karg);
		free(kenv);
		close_vfs(in);
		return -1;
	}

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

bool process_found_children(pid_t pid, struct process *process)
{
	spin_lock(&process->children_lock);

	if(process->children)
	{
		/* if we have children, return true */
		spin_unlock(&process->children_lock);
		return true;
	}

	for(struct process *p = process->children; p != NULL; p = p->next_sibbling)
	{
		if(p->pid == pid)
		{
			spin_unlock(&process->children_lock);
			return true;
		}
	}

	spin_unlock(&process->children_lock);
	return false;
}

bool wait4_find_dead_process(struct process *process, pid_t pid, int *wstatus, pid_t *ret)
{
	bool looking_for_any = pid < 0;

	for(struct process *p = process->children; p != NULL; p = p->next_sibbling)
	{
		if((p->pid == pid || looking_for_any) && p->has_exited)
		{
			if(wstatus)
			{
				errno = EFAULT;
				if(copy_to_user(wstatus, &p->exit_code, sizeof(int)) < 0)
					return false;
			}
			*ret = p->pid;

			spin_unlock(&process->children_lock);
			process_end(p);

			return true;
		}
	}

	return false;
}

pid_t sys_wait4(pid_t pid, int *wstatus, int options, struct rusage *usage)
{
	struct process *current = get_current_process();

	if(!process_found_children(pid, current))
	{
		return -ECHILD;
	}

	while(true)
	{
		if(signal_is_pending())
			return -EINTR;

		spin_lock(&current->children_lock);

		pid_t ret;
		errno = 0;

		if(wait4_find_dead_process(current, pid, wstatus, &ret))
		{
			return ret;
		}
		else
		{
			if(errno == EFAULT)
			{
				spin_unlock(&current->children_lock);
				return -EFAULT;
			}
		}

		spin_unlock(&current->children_lock);

		sem_wait(&current->wait_sem);
	}

	return 0;
}

void process_copy_current_sigmask(struct thread *dest)
{
	memcpy(&dest->sinfo.sigmask, &get_current_thread()->sinfo.sigmask, sizeof(sigset_t));
}

pid_t sys_fork(struct syscall_frame *ctx)
{
	struct process 	*proc;
	struct process 	*child;
	thread_t 	*to_be_forked;

	proc = (struct process*) get_current_process();
	to_be_forked = get_current_thread();	
	/* Create a new process */
	child = process_create(strdup(proc->cmd_line), &proc->ctx, proc);

	if(!child)
		return -ENOMEM;

	/* Fork the vmm data and the address space */
	if(vm_fork_address_space(&child->address_space) < 0)
		return -ENOMEM;

	/* Fork and create the new thread */
	struct thread *new = process_fork_thread(to_be_forked, child, ctx);

	if(!new)
	{
		panic("TODO: Add process destruction here.\n");
	}

	process_copy_current_sigmask(new);

	sched_start_thread(new);

	// Return the pid to the caller
	return child->pid;
}

int make_wait4_wstatus(int signum, bool core_dumped, int exit_code)
{
	int wstatus = 0;

	wstatus = ((int) core_dumped << 7);

	if(signum == 0)
	{
		wstatus |= ((exit_code & 0xff) << 8);
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
	if(current->pid == 1)
	{
		printk("Panic: %s exited with signal %d!\n",
			get_current_process()->cmd_line, signum);
		ENABLE_INTERRUPTS();
		for(;;);
	}

	current->has_exited = 1;
	current->exit_code = make_wait4_wstatus(signum, false, 0);

	/* TODO: Support multi-threaded processes */
	thread_t *current_thread = get_current_thread();

	process_destroy(current_thread);
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

	/* TODO: Support multi-threaded processes */
	thread_t *current_thread = get_current_thread();

	process_destroy(current_thread);
}

uint64_t sys_getpid(void)
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

	vm_destroy_addr_space(&current->address_space);
}

void process_destroy_file_descriptors(struct process *process)
{
	ioctx_t *ctx = &process->ctx;
	struct file **table = ctx->file_desc;
	mutex_lock(&ctx->fdlock);

	for(int i = 0; i < ctx->file_desc_entries; i++)
	{
		if(!table[i])
			continue;

		table[i]->refcount--;

		if(!table[i]->refcount)
		{
			object_unref(&table[i]->vfs_node->i_object);
			free(table[i]);
		}
	}

	free(table);

	ctx->file_desc = NULL;
	ctx->file_desc_entries = 0;

	mutex_unlock(&ctx->fdlock);
}

void process_remove_from_list(struct process *process)
{
	spin_lock(&process_list_lock);
	/* TODO: Make the list a doubly-linked one, so we're able to tear it down more easily */
	if(first_process == process)
	{
		first_process = first_process->next;
		if(process_tail == process)
			process_tail = first_process;
	}
	else
	{
		struct process *p;
		for(p = first_process; p->next != process && p->next; p = p->next);
		
		assert(p->next != NULL);

		p->next = process->next;

		if(process_tail == process)
			process_tail = p;
	}

	spin_unlock(&process_list_lock);

	/* Remove from the sibblings list */

	spin_lock(&process->parent->children_lock);

	if(process->prev_sibbling)
		process->prev_sibbling->next_sibbling = process->next_sibbling;
	else
		process->parent->children = process->next_sibbling;

	if(process->next_sibbling)
		process->next_sibbling->prev_sibbling = process->prev_sibbling;

	spin_unlock(&process->parent->children_lock);
}

void process_wait_for_dead_threads(struct process *process)
{
	bool goaway = false;

	while(!goaway)
	{
		goaway = true;

		list_for_every(&process->thread_list)
		{
			struct thread *t = container_of(l, struct thread, thread_list_head);

			if(t->status != THREAD_DEAD)
			{
				goaway = false;
				continue;
			}
			else
			{
				if(t->flags & THREAD_IS_DYING)
					goaway = false;
			}
		}

		cpu_relax();
	}
}

void process_end(struct process *process)
{
	process_remove_from_list(process);
	
	process_wait_for_dead_threads(process);

	free(process->cmd_line);
	process->cmd_line = NULL;

	if(process->ctx.name)
		free((void *) process->ctx.name);
	
	if(process->ctx.cwd)
		object_unref(&process->ctx.cwd->i_object);

	list_for_every_safe(&process->thread_list)
	{
		struct thread *thread = container_of(l, struct thread, thread_list_head);
		thread_destroy(thread);
	}

	futex_free_queue(process);
	free(process);
}

void process_reparent_children(struct process *process)
{
	spin_lock(&process->children_lock);

	/* In POSIX, reparented children get to be children of PID 1 */
	struct process *new_parent = first_process;

	if(!process->children)
	{
		spin_unlock(&process->children_lock);
		return;
	}

	for(struct process *c = process->children; c != NULL; c = c->next_sibbling)
		c->parent = new_parent; 
	
	process_append_children(new_parent, process->children);

	spin_unlock(&process->children_lock);
}

void process_kill_other_threads(void)
{
	struct process *current = get_current_process();
	struct thread *current_thread = get_current_thread();
	unsigned long threads_to_wait_for = 0;
	/* TODO: Fix thread killing */
	list_for_every(&current->thread_list)
	{
		struct thread *t = container_of(l, struct thread, thread_list_head);
		if(t == current_thread)
			continue;
		t->flags |= THREAD_SHOULD_DIE;
		threads_to_wait_for++;
	}

	while(threads_to_wait_for != 0)
	{
		list_for_every_safe(&current->thread_list)
		{
			struct thread *t = container_of(l, struct thread, thread_list_head);

			if(t && t->status == THREAD_DEAD &&
				(t->flags & THREAD_SHOULD_DIE) &&
				!(t->flags & THREAD_IS_DYING))
			{
				threads_to_wait_for--;
				current->nr_threads--;
				t->flags &= ~THREAD_SHOULD_DIE;	
				list_remove(l);
			}
		}
	}
}

void process_destroy(thread_t *current_thread)
{
	/* TODO: Fix this. This means file closing routines can't sleep,
	 * which is profoundly borken
	*/
	/* Enter critical section */
	//sched_disable_preempt();

	struct process *current = get_current_process();
	process_kill_other_threads();

	/* Firstly, destroy the address space */
	process_destroy_aspace();

	process_destroy_file_descriptors(current);

	process_reparent_children(current);

	for(struct proc_event_sub *s = current->sub_queue; s; s = s->next)
	{
		s->valid_sub = false;
	}

	/* Set this in this order exactly */
	current_thread->flags = THREAD_IS_DYING;
	current_thread->status = THREAD_DEAD;

	/* Finally, wake up any possible concerned (waiting :D) parents */
	sem_signal(&current->parent->wait_sem);

	//sched_enable_preempt();

	sched_yield();

	while(true);
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
		if(extrusive_list_add(&tracer->tracees, tracee) < 0)
			return errno = ENOMEM, -1;
	}
	return 0;
}

/* Finds a pid that tracer is tracing */
struct process *process_find_tracee(struct process *tracer, pid_t pid)
{
	struct extrusive_list_head *list = &tracer->tracees;
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
	spin_lock(&process->thread_list_lock);

	list_add_tail(&thread->thread_list_head, &process->thread_list);

	spin_unlock(&process->thread_list_lock);

	process->nr_threads++;
}

#define CLONE_FORK		(1 << 0)
#define CLONE_SPAWNTHREAD	(1 << 1)
long valid_flags = CLONE_FORK | CLONE_SPAWNTHREAD;

int sys_clone(int (*fn)(void *), void *child_stack, int flags, void *arg, pid_t *ptid, void *tls)
{
	if(flags & ~valid_flags)
		return -EINVAL;
	if(!vm_find_region(fn))
		return -EINVAL;
	if(flags & CLONE_FORK)
		return -EINVAL; /* TODO: Add CLONE_FORK */
	thread_callback_t start = (thread_callback_t) fn;

	registers_t regs;
	memset(&regs, 0, sizeof(registers_t));
	regs.rsp = (uint64_t) child_stack;
	regs.rflags = 0x202;

	thread_t *thread = sched_spawn_thread(&regs, start, arg, tls);
	if(!thread)
		return -errno;

	if(copy_to_user(ptid, &thread->id, sizeof(pid_t)) < 0)
	{
		thread_destroy(thread);
		return -errno;
	}

	process_add_thread(get_current_process(), thread);
	sched_start_thread(thread);

	return 0;
}

void sys_exit_thread(int value)
{
	/* Okay, so the libc called us. That means we can start destroying the thread */
	/* NOTE: I'm not really sure if musl destroyed the user stack and fs,
	 * and if we should anything to free them */
	/* Destroy the thread */
	sched_die();
	/* aaaaand we'll never return back to user-space, so just hang on */
	sched_yield();
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
	panic("broken");
}

void process_stop(struct process *p)
{
	panic("broken");
}
