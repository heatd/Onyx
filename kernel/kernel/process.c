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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <kernel/compiler.h>
#include <kernel/elf.h>
#include <kernel/process.h>
#include <kernel/task_switching.h>
#include <kernel/cpu.h>
#include <kernel/random.h>
#include <pthread_kernel.h>

extern PML4 *current_pml4;
process_t *first_process = NULL;
process_t *current_process = NULL;
uint64_t current_pid = 1;
process_t *process_create(const char *cmd_line, ioctx_t *ctx, process_t *parent)
{
	process_t *proc = malloc(sizeof(process_t));
	if(!proc)
		return errno = ENOMEM, NULL;
	memset(proc, 0, sizeof(process_t));
	proc->pid = current_pid;
	current_pid++;
	proc->cmd_line = cmd_line;
	// TODO: Setup proc->ctx
	if(ctx)
		memcpy(&proc->ctx, ctx, sizeof(ioctx_t));
	if(parent)
		proc->parent = parent;
	if(!first_process)
		first_process = proc;
	else
	{
		process_t *it = current_process;
		while(it->next) it = it->next;
		it->next = proc;
	}
	return proc;
}
static int c;
void process_create_thread(process_t *proc, thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp)
{
	c++;
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
		sched_destroy_thread(thread);
}
extern int curr_id;
void process_fork_thread(process_t *dest, process_t *src, int thread_index)
{
	dest->threads[thread_index] = malloc(sizeof(thread_t));
	memcpy(dest->threads[thread_index], src->threads[thread_index], sizeof(thread_t));
	thread_add(dest->threads[thread_index]);
	dest->threads[thread_index]->id = curr_id++;
	dest->threads[thread_index]->owner = dest;
}
process_t *get_process_from_pid(pid_t pid)
{
	process_t *p = first_process;
	for(;p;p = p->next)
	{
		if(p->pid == pid)
			return p;
	}
	return NULL;
}
static spinlock_t execve_spl;
extern _Bool is_spawning;
int sys_execve(char *path, char *argv[], char *envp[])
{
	if(!vmm_is_mapped(path))
		return errno =-EINVAL;
	if(!vmm_is_mapped(argv))
		return errno =-EINVAL;
	if(!vmm_is_mapped(envp))
		return errno =-EINVAL;

	/* Create a new address space */
	avl_node_t *tree;
	current_process->cr3 = vmm_clone_as(&tree);

	current_process->tree = tree;
	/* Open the file */
	vfsnode_t *in = open_vfs(fs_root, path);
	if (!in)
	{
		errno =-ENOENT;
		perror(NULL);
		release_spinlock(&execve_spl);
		return errno =-ENOENT;
	}
	/* Allocate a buffer and read the whole file to it */
	char *buffer = malloc(in->size);
	if (!buffer)
		return errno =-ENOMEM;

	in->read(0, in->size, buffer, in);

	int nargs = 0;
	size_t arg_string_len = strlen(path) + 1;
	for(; argv[nargs]; nargs++)
		arg_string_len += strlen(argv[nargs]) + 1;
	int nenvp = 0;
	size_t envp_string_len = 0;
	for(; envp[nenvp]; nenvp++)
		envp_string_len += strlen(envp[nenvp]) + 1;

	char *intermediary_buffer_args = malloc(arg_string_len);
	memset(intermediary_buffer_args, 0, arg_string_len);
	volatile char *temp = intermediary_buffer_args;
	for(int i = 0; i < nargs; i++)
	{
		strcpy((char *) temp, argv[i]);
		temp += strlen(argv[i]) + 1;
	}
	char *intermediary_buffer_envp = malloc(envp_string_len);
	memset(intermediary_buffer_envp, 0, envp_string_len);
	temp = intermediary_buffer_envp;
	for(int i = 0; i < nenvp; i++)
	{
		strcpy((char*) temp, envp[i]);
		temp += strlen(envp[i]) + 1;
	}
	DISABLE_INTERRUPTS();

	paging_load_cr3(current_process->cr3);

	/* Map argv and envp */
	char **new_args = vmm_allocate_virt_address(0, vmm_align_size_to_pages(sizeof(void*) * nargs), VMM_TYPE_REGULAR, VMM_USER|VMM_WRITE);
	char **new_envp = vmm_allocate_virt_address(0, vmm_align_size_to_pages(sizeof(void*) * nenvp), VMM_TYPE_REGULAR, VMM_USER|VMM_WRITE);
	vmm_map_range(new_args, vmm_align_size_to_pages(sizeof(void*) * nargs), VMM_WRITE | VMM_USER | VMM_NOEXEC);
	vmm_map_range(new_envp, vmm_align_size_to_pages(sizeof(void*) * nenvp), VMM_WRITE | VMM_USER | VMM_NOEXEC);
	
	/* Map the actual strings */
	char *argv_buffer = vmm_allocate_virt_address(0, vmm_align_size_to_pages(arg_string_len), VMM_TYPE_REGULAR, VMM_USER|VMM_WRITE);
	char *envp_buffer = vmm_allocate_virt_address(0, vmm_align_size_to_pages(envp_string_len), VMM_TYPE_REGULAR, VMM_USER|VMM_WRITE);
	vmm_map_range(argv_buffer, vmm_align_size_to_pages(arg_string_len), VMM_WRITE | VMM_USER | VMM_NOEXEC);
	vmm_map_range(envp_buffer, vmm_align_size_to_pages(envp_string_len), VMM_WRITE | VMM_USER | VMM_NOEXEC);
	
	/* Copy the buffers */
	memcpy(argv_buffer, intermediary_buffer_args, arg_string_len);
	memcpy(envp_buffer, intermediary_buffer_envp, envp_string_len);
	temp = argv_buffer;
	for(int i = 0; i < nargs; i++)
	{
		new_args[i] = (char*) temp;
		temp += strlen(new_args[i]) + 1;
	}
	temp = envp_buffer;
	for(int i = 0; i < nenvp; i++)
	{
		new_envp[i] = (char*) temp;
		temp += strlen(new_envp[i]) + 1;
	}

	void *entry = elf_load((void *) buffer);

	thread_t *t = sched_create_main_thread((thread_callback_t) entry, 0, nargs, new_args, new_envp);
		
	sched_destroy_thread(current_process->threads[0]);

	/* Set the appropriate uid and gid */
	if(current_process->setuid != 0)
		current_process->uid = current_process->setuid;
	if(current_process->setgid != 0)
		current_process->gid = current_process->setgid;
	current_process->setuid = 0;
	current_process->setgid = 0;
	t->owner = current_process;
	current_process->threads[0] = t;

	/* Allocate the program's data break */
	current_process->brk = vmm_allocate_virt_address(0, 1, VMM_TYPE_HEAP, VMM_WRITE | VMM_NOEXEC | VMM_USER);

	vmm_map_range(current_process->brk, 1, VMM_WRITE | VMM_NOEXEC | VMM_USER);

	/* Prepare the auxv */
	Elf64_auxv_t *auxv = (Elf64_auxv_t *) current_process->threads[0]->user_stack_bottom;
	unsigned char *scratch_space = (unsigned char *) (auxv + 37);
	for(int i = 0; i < 38; i++)
	{
		if(i != 0)
			auxv[i].a_type = i;
		if(i == 37)
			auxv[i].a_type = 0;
		switch(i)
		{
			case AT_PAGESZ:
				auxv[i].a_un.a_val = PAGE_SIZE;
				break;
			case AT_UID:
				auxv[i].a_un.a_val = current_process->uid;
				break;
			case AT_GID:
				auxv[i].a_un.a_val = current_process->gid;
				break;
			case AT_RANDOM:
				get_entropy((char*) scratch_space, 16);
				printf("Random: %x%x\n", *(uint64_t*) scratch_space, *(uint64_t*) scratch_space+1);
				scratch_space += 16;
				break;
		}
	}
	registers_t *regs = (registers_t *) current_process->threads[0]->kernel_stack;
	regs->rcx = (uintptr_t) auxv;
	
	current_process->fs = (uintptr_t) vmm_allocate_virt_address(0, 1, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	vmm_map_range((void*) current_process->fs, 1, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	pthread_t *p = (struct pthread*) current_process->fs;
	p->self = (pthread_t*) p;

	p->tid = current_process->threads[0]->id;
	p->pid = current_process->pid;

	release_spinlock(&execve_spl);
	ENABLE_INTERRUPTS();
	while(1);
}
pid_t sys_getppid()
{
	if(current_process->parent)
		return current_process->parent->pid;
	else
		return -1;
}
int sys_wait(int *exitstatus)
{
	process_t *i = current_process;
	_Bool has_one_child = 0;
loop:
	while(i)
	{
		if(i->parent == current_process)
			has_one_child = 1;
		if(i->parent == current_process && i->has_exited == 1)
			return i->pid;
		i = i->next;
	}
	i = first_process;
	if(has_one_child == 0)
		return -1;
	goto loop;
}
spinlock_t fork_spl;
extern size_t num_areas;
pid_t sys_fork(syscall_ctx_t *ctx)
{

	process_t *proc = current_process;
	if(!proc)
		return -1;
	/* Create a new process */
	process_t *child = process_create(current_process->cmd_line, &proc->ctx, proc); /* Create a process with the current
							  			  * process's info */
	if(!child)
		return -1;

	/* Fork the vmm data and the address space */
	avl_node_t *areas;
	acquire_spinlock(&fork_spl);
	PML4 *new_pt = vmm_fork_as(&areas); // Fork the address space
	release_spinlock(&fork_spl);
	child->tree = areas;
	child->cr3 = new_pt; // Set the new cr3

	/* We need to disable the interrupts for a moment, because thread_add adds it to the queue, 
	   and the thread isn't ready yet */
	
	DISABLE_INTERRUPTS();
	/* Fork and create the new thread */
	process_fork_thread(child, proc, 0);

	child->threads[0]->kernel_stack = vmalloc(2, VM_TYPE_STACK, VM_WRITE | VM_NOEXEC | VM_GLOBAL);
	if(!child->threads[0]->kernel_stack)
	{
		free(child->threads[0]);
		sched_destroy_thread(child->threads[0]);
		free(child);
		ENABLE_INTERRUPTS();
		return errno =-ENOMEM;
	}
	child->threads[0]->kernel_stack = (uintptr_t *) ((unsigned char *)child->threads[0]->kernel_stack + 0x2000);
	child->threads[0]->kernel_stack_top = child->threads[0]->kernel_stack;
	child->threads[0]->kernel_stack = sched_fork_stack(ctx, child->threads[0]->kernel_stack);
	
	ENABLE_INTERRUPTS();
	// Return the pid to the caller
	return child->pid;
}
void sys__exit(int status)
{
	DISABLE_INTERRUPTS();
	if(current_process->pid == 1)
	{
		printf("Panic: %s returned!\n", current_process->cmd_line);
		extern int syscalls;
		printf("%u system calls!\n", syscalls);
		ENABLE_INTERRUPTS();
		for(;;);
	}
	current_process->has_exited = status;
	ENABLE_INTERRUPTS();
	while(1) asm volatile("hlt");
}
uint64_t sys_getpid()
{
	return current_process->pid;
}
int sys_personality(unsigned long val)
{
	// TODO: Use this syscall for something. This might be potentially very useful
	current_process->personality = val;
	return 0;
}
int sys_setuid(uid_t uid)
{
	if(uid == 0 && current_process->uid != 0)
		return errno =-EPERM;
	current_process->setuid = uid;
	return 0;
}
int sys_setgid(gid_t gid)
{
	current_process->setgid = gid;
	return 0;
}