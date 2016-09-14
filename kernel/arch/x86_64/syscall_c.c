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
#include <unistd.h>
#include <kernel/tty.h>
#include <sys/types.h>
#include <kernel/process.h>
#include <kernel/vmm.h>
#include <errno.h>
#include <kernel/elf.h>
#include <kernel/panic.h>
#include <sys/mman.h>
#include <drivers/rtc.h>
#include <sys/time.h>
const uint32_t SYSCALL_MAX_NUM = 21;
spinlock_t lseek_spl;
off_t sys_lseek(int fd, off_t offset, int whence)
{
	acquire_spinlock(&lseek_spl);
	if (fd > UINT16_MAX)
	{
		release_spinlock(&lseek_spl);
		return errno = EBADFD, -1;
	}
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[fd] == NULL)
	{
		release_spinlock(&lseek_spl);
		return errno = EBADFD, -1;
	}
	if(whence == SEEK_CUR)
		ioctx->file_desc[fd]->seek += offset;
	else if(whence == SEEK_SET)
		ioctx->file_desc[fd]->seek = offset;
	else if(whence == SEEK_END)
		ioctx->file_desc[fd]->seek = ioctx->file_desc[fd]->vfs_node->size;
	else
	{
		release_spinlock(&lseek_spl);
		return errno = EINVAL;
	}
	release_spinlock(&lseek_spl);
	return ioctx->file_desc[fd]->seek;
}
spinlock_t write_spl;
ssize_t sys_write(int fd, const void *buf, size_t count)
{
	acquire_spinlock(&write_spl);
	if(fd == 1)
		tty_write(buf, count);
	release_spinlock(&write_spl);
	return count;
}
void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *mapping_addr = NULL;
	// Calculate the pages needed for the overall size
	size_t pages = length / PAGE_SIZE;
	if(length % PAGE_SIZE)
		pages++;
	
	int vm_prot = 0;
	vm_prot |= VMM_USER;
	if(prot & PROT_WRITE)
		vm_prot |= VMM_WRITE;
	if(!(prot & PROT_EXEC))
		vm_prot |= VMM_NOEXEC;
	if(!addr) // Specified by posix, if addr == NULL, guess an address
		mapping_addr = vmm_allocate_virt_address(0, pages, VMM_TYPE_REGULAR, vm_prot);
	else
	{
		mapping_addr = vmm_reserve_address(addr, pages, VMM_TYPE_REGULAR, vm_prot);
		if(!mapping_addr)
			mapping_addr = vmm_allocate_virt_address(0, pages, VMM_TYPE_REGULAR, vm_prot);
	}
	printf("Returning %p\n", mapping_addr);
	if(!mapping_addr)
		return errno = ENOMEM, NULL;
	if(!vmm_map_range(mapping_addr, pages, vm_prot))
		return errno = ENOMEM, NULL;
	return mapping_addr;
}
int sys_munmap(void *addr, size_t length)
{
	if ((uintptr_t) addr >= VM_HIGHER_HALF)
		return errno = EINVAL, -1;
	size_t pages = length / PAGE_SIZE;
	if(length % PAGE_SIZE)
		pages++;
	if(!((uintptr_t) addr & 0xFFFFFFFFFFFFF000))
		return errno = EINVAL, -1;
	vmm_unmap_range(addr, pages);
	vmm_destroy_mappings(addr, pages);
	return 0;
}
int sys_mprotect(void *addr, size_t len, int prot)
{
	if(!vmm_is_mapped(addr))
		return -1;
	int vm_prot = 0;
	if(prot & PROT_WRITE)
		vm_prot |= VMM_WRITE;
	if(!(prot & PROT_EXEC))
		vm_prot |= VMM_NOEXEC;
	size_t pages = len / PAGE_SIZE;
	if(len % PAGE_SIZE)
		pages++;
	vmm_change_perms(addr, pages, vm_prot);
	return 0;
}
spinlock_t read_spl;
extern char keyboard_buffer[];
extern volatile size_t keyboard_pos;
ssize_t sys_read(int fd, const void *buf, size_t count)
{
	acquire_spinlock(&read_spl);
	if (fd == STDIN_FILENO)
	{
		while(keyboard_pos == 0);
		memcpy(buf, &keyboard_buffer[keyboard_pos-1], count);
		memset(keyboard_buffer, 0, 1024);
		keyboard_pos = 0;
		release_spinlock(&read_spl);
		return count;
	}
	ioctx_t *ioctx = &current_process->ctx;
	if( fd > UINT16_MAX)
	{
		release_spinlock(&read_spl);
		return errno = EBADFD;
	}
	if(ioctx->file_desc[fd] == NULL)
	{
		release_spinlock(&read_spl);
		return errno = EBADFD;
	}
	if(!buf)
	{
		release_spinlock(&read_spl);
		return errno = EINVAL;
	}
	ssize_t size = read_vfs(ioctx->file_desc[fd]->seek, count, (char*)buf, ioctx->file_desc[fd]->vfs_node);
	ioctx->file_desc[fd]->seek += size;
	release_spinlock(&read_spl);
	return size;
}
uint64_t sys_getpid()
{
	return current_process->pid;
}
spinlock_t open_spl;
int sys_open(const char *filename, int flags)
{
	acquire_spinlock(&open_spl);
	ioctx_t *ioctx = &current_process->ctx;
	for(int i = 0; i < UINT16_MAX; i++)
	{
		if (i <= 2)
			continue;
		if(ioctx->file_desc[i] == NULL)
		{
			ioctx->file_desc[i] = malloc(sizeof(file_desc_t));
			memset(ioctx->file_desc[i], 0, sizeof(file_desc_t));
			ioctx->file_desc[i]->vfs_node = open_vfs(fs_root, filename);
			ioctx->file_desc[i]->vfs_node->refcount++;
			ioctx->file_desc[i]->seek = 0;
			ioctx->file_desc[i]->flags = flags;
			release_spinlock(&open_spl);
			printf("Returning fd %i\n", i);
			return i;
		}
	}
	release_spinlock(&open_spl);
	return errno = EMFILE;
}
spinlock_t close_spl;
int sys_close(int fd)
{
	acquire_spinlock(&close_spl);
	if(fd > UINT16_MAX) 
	{
		release_spinlock(&close_spl);
		return errno = EBADFD;
	}
	ioctx_t *ioctx = &current_process->ctx;	
	if(ioctx->file_desc[fd] == NULL)
	{
		release_spinlock(&close_spl);
		return errno = EBADFD;
	}
	close_vfs(ioctx->file_desc[fd]->vfs_node);
	ioctx->file_desc[fd]->vfs_node->refcount--;
	if(ioctx->file_desc[fd]->vfs_node->refcount == 0)
	{
		free(ioctx->file_desc[fd]->vfs_node);
		free(ioctx->file_desc[fd]);
	}
	release_spinlock(&close_spl);
	return 0;
}
spinlock_t dup_spl;
int sys_dup(int fd)
{
	acquire_spinlock(&dup_spl);
	if(fd > UINT16_MAX)
	{
		release_spinlock(&dup_spl);
		return errno = EBADFD;
	}
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[fd] == NULL)
	{
		release_spinlock(&dup_spl);
		return errno = EBADFD;
	}
	for(int i = 0; i < UINT16_MAX; i++)
	{
		if(ioctx->file_desc[i] == NULL)
		{
			ioctx->file_desc[i] = ioctx->file_desc[fd];
			ioctx->file_desc[fd]->vfs_node->refcount++;
			release_spinlock(&dup_spl);
			return i;
		}
	}
	return errno = EMFILE;
}
spinlock_t dup2_spl;
int sys_dup2(int oldfd, int newfd)
{
	acquire_spinlock(&dup2_spl);
	if(oldfd > UINT16_MAX)
	{
		release_spinlock(&dup2_spl);
		return errno = EBADFD;
	}
	if(newfd > UINT16_MAX)
	{
		release_spinlock(&dup2_spl);
		return errno = EBADFD;
	}
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[oldfd] == NULL)
	{
		release_spinlock(&dup2_spl);
		return errno = EBADFD;
	}
	if(ioctx->file_desc[newfd])
		sys_close(newfd);
	ioctx->file_desc[newfd] = ioctx->file_desc[oldfd];
	ioctx->file_desc[newfd]->vfs_node->refcount++;
	release_spinlock(&dup2_spl);
	return newfd;
}
void sys__exit(int status)
{
	asm volatile("cli");
	if(current_process->pid == 1)
	{
		printf("Panic: %s returned!\n", current_process->cmd_line);
		asm volatile("sti");
		for(;;) asm volatile("pause");
	}
	current_process->has_exited = status;
	sched_destroy_thread(get_current_thread());
	asm volatile("sti");
	while(1) asm volatile("hlt");
}
static spinlock_t posix_spawn_spl;
extern PML4 *current_pml4;
int sys_posix_spawn(pid_t *pid, const char *path, void *file_actions, void *attrp, char **const argv, char **const envp)
{
	acquire_spinlock(&posix_spawn_spl);
	// Create a new clean process
	process_t *new_proc = process_create(path, &current_process->ctx, current_process);
	*pid = new_proc->pid;
	if(!new_proc)
	{
		release_spinlock(&posix_spawn_spl);
		return errno = ENOMEM, -1;
	}
	// Parse through the argv
	size_t num_args = 1;
	size_t total_size = strlen(path) + 1 + sizeof(uintptr_t);
	char **n = argv;
	
	while(*n != NULL)
	{
		num_args++;
		total_size += strlen(*argv) + 1;
		total_size += sizeof(uintptr_t);
		n++;
	}
	
	size_t pages = total_size / PAGE_SIZE;
	
	if(total_size % PAGE_SIZE)
		pages++;
	// Allocate some memory for the args
	uintptr_t *arguments = vmm_allocate_virt_address(VM_KERNEL, pages, VMM_TYPE_REGULAR, VMM_NOEXEC | VMM_WRITE);
	vmm_map_range(arguments, pages,  VMM_NOEXEC | VMM_WRITE);
	// Copy all the data
	char *argument_strings = (char*)arguments + num_args * sizeof(uintptr_t);
	for(size_t i = 0; i < num_args; i++)
	{
		if( i == 0)
		{
			arguments[i] = (uint64_t)argument_strings;
			strcpy(argument_strings, path);
			argument_strings += strlen(path) + 1;
			continue;
		}
		
		arguments[i] = (uint64_t)argument_strings;
		strcpy(argument_strings, argv[i-1]);
		argument_strings += strlen(argv[i-1]) + 1;
	}
	/*size_t total_env = 0;
	size_t num_vars = 0;
	n = envp;
	while(*n != NULL)
	{	
		num_vars++;
		total_size += strlen(*envp) + 1;
		total_size += sizeof(uintptr_t);
		n++;
	}
	size_t env_pages = total_size / PAGE_SIZE;
	if(total_size % PAGE_SIZE)
		env_pages++;
	uintptr_t *variables = vmm_allocate_virt_address(VM_KERNEL, env_pages, VMM_TYPE_REGULAR, VMM_NOEXEC | VMM_WRITE | VMM_USER);
	vmm_map_range(variables, env_pages,  VMM_NOEXEC | VMM_WRITE | VMM_USER);
	memset(variables, 0 ,PAGE_SIZE * env_pages);
	char *variable_strings = (char*)variables + num_vars * sizeof(uintptr_t);
	for(size_t i = 0; i < num_vars; i++)
	{	
		variables[i] = (uint64_t)variable_strings;
		strcpy(variable_strings, envp[i]);
		variable_strings += strlen(envp[i]) + 1;
	}*/
	// Open the elf file and read from it
	vfsnode_t *in = open_vfs(fs_root, path);
	if (!in)
	{
		printf("%s: No such file or directory\n", path);
		return errno = ENOENT, 1;
	}
	
	char *buffer = malloc(in->size);
	if (!buffer)
		return errno = ENOMEM, -1;
	size_t read = read_vfs(0, in->size, buffer, in);
	if (read != in->size)
		return errno = EAGAIN, -1;
	vmm_entry_t *areas;
	size_t num_r;
	PML4 *new_pt = vmm_clone_as(&areas, &num_r);
	asm volatile ("mov %0, %%cr3" :: "r"(new_pt)); /* We can't use paging_load_cr3 because that would change current_pml4
							* which we will need for later 
							*/
	new_proc->num_areas = num_r;
	uintptr_t *new_arguments = vmm_allocate_virt_address(0, pages, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	vmm_map_range(new_arguments, pages, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	memcpy(new_arguments, arguments, pages * PAGE_SIZE);
	for(size_t i = 0; i < num_args; i++)
	{
		new_arguments[i] = ((uint64_t)new_arguments[i] - (uint64_t)arguments) + (uint64_t)new_arguments;
	}
	/*uintptr_t *new_envp = vmm_allocate_virt_address(0, env_pages, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	vmm_map_range(new_envp, env_pages, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	memcpy(new_envp, variables, env_pages * PAGE_SIZE);
	for(size_t i = 0; i < num_vars; i++)
	{
		new_envp[i] = ((uint64_t)new_envp[i] - (uint64_t)variables) + (uint64_t)new_envp;
	}*/
	void *entry = elf_load((void *) buffer);
	// Create the new thread
	process_create_thread(new_proc, (ThreadCallback) entry, 0, num_args, (char**)new_arguments, NULL);
	new_proc->cr3 = new_pt;
	vmm_stop_spawning();
	asm volatile("mov %0, %%cr3"::"r"(current_pml4));
	release_spinlock(&posix_spawn_spl);
	return 0;
}
spinlock_t fork_spl;
extern uintptr_t forkretregs;
extern size_t num_areas;
extern uintptr_t forkstack;
extern uintptr_t forkret;
pid_t sys_fork()
{	
	uintptr_t *forkstackregs = (uintptr_t*)forkretregs; // Go to the start of the little reg save
	process_t *proc = current_process;
	if(!proc)
		return -1;
	process_t *forked = process_create(current_process->cmd_line, &proc->ctx, proc); /* Create a process with the current
								  			  * process's info */
	if(!forked)
		return -1;
	vmm_entry_t *areas;
	acquire_spinlock(&fork_spl);
	PML4 *new_pt = vmm_fork_as(&areas); // Fork the address space
	release_spinlock(&fork_spl);
	forked->areas = areas;
	forked->num_areas = num_areas;
	forked->cr3 = new_pt; // Set the new cr3

	process_fork_thread(forked, proc, 0); // Fork the thread (basically memcpy)
	forked->threads[0]->kernel_stack = malloc(0x2000); // TODO: Is this a bad hack?
	if(!forked->threads[0]->kernel_stack)
		return -1;
	forked->threads[0]->kernel_stack += 0x2000;
	forked->threads[0]->kernel_stack_top = forked->threads[0]->kernel_stack;

	uintptr_t *stack = (uint64_t*)forked->threads[0]->kernel_stack;

	stack = sched_fork_stack(stack, forkstackregs, (uintptr_t*) forkstack, forkret);

	forked->threads[0]->kernel_stack = stack;

	// Return the pid to the caller
	return forked->pid;
}
int sys_mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data)
{
	read_partitions();
	return 0;
}
uint64_t sys_nosys()
{
	return (uint64_t) -1;
}
uint64_t sys_brk(void *addr)
{
	if(addr == NULL)
		return current_process->brk;
	else
		current_process->brk = addr;
	return 0;
}
pid_t sys_getppid()
{
	if(current_process->parent)
		return current_process->parent->pid;
	else
		return -1;
}
extern process_t *first_process;
static spinlock_t execve_spl;
int sys_execve(char *path, char *argv[], char *envp[])
{
	acquire_spinlock(&execve_spl);
	size_t areas;
	vmm_entry_t *entries;
	current_process->cr3 = vmm_clone_as(&entries, &areas);
	current_process->areas = entries;
	current_process->num_areas = areas;
	vfsnode_t *in = open_vfs(fs_root, path);
	if (!in)
	{
		release_spinlock(&execve_spl);
		return errno = ENOENT;
	}
	char *buffer = malloc(in->size);
	if (!buffer)
		return errno = ENOMEM;
	size_t read = read_vfs(0, in->size, buffer, in);
	if (read != in->size)
		return errno = EAGAIN;
	asm volatile ("mov %0, %%cr3" :: "r"(current_process->cr3)); /* We can't use paging_load_cr3 because that would change current_pml4
							* which we will need for later 
							*/
	void *entry = elf_load((void *) buffer);
	asm volatile("cli");
	thread_t *t = sched_create_thread((ThreadCallback) entry,0, NULL);
	t->owner = current_process;
	current_process->threads[0] = t;
	vmm_stop_spawning();
	release_spinlock(&execve_spl);
	asm volatile ("mov %0, %%cr3" :: "r"(current_pml4)); /* We can't use paging_load_cr3 because that would change current_pml4
							* which we will need for later 
							*/
	asm volatile("sti");
	while(1);
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
time_t sys_time(time_t *s)
{
	if(s)
		*s = get_posix_time();
	return get_posix_time();
}
int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	if(tv)
	{
		tv->tv_sec = get_posix_time();
		tv->tv_usec = 0;
	}
	if(tz)
	{
		tz->tz_minuteswest = 0;
		tz->tz_dsttime = 0; 
	}
	return 0;
}
void *syscall_list[] =
{
	[0] = (void*) sys_write,
	[1] = (void*) sys_read,
	[2] = (void*) sys_open,
	[3] = (void*) sys_close,
	[4] = (void*) sys_dup,
	[5] = (void*) sys_dup2,
	[6] = (void*) sys_getpid,
	[7] = (void*) sys_lseek,
	[8] = (void*) sys__exit,
	[9] = (void*) sys_posix_spawn,
	[10] = (void*) sys_fork,
	[11] = (void*) sys_mmap,
	[12] = (void*) sys_munmap,
	[13] = (void*) sys_mprotect,
	[14] = (void*) sys_mount,
	[15] = (void*) sys_execve,
	[16] = (void*) sys_brk,
	[17] = (void*) sys_nosys,
	[18] = (void*) sys_getppid,
	[19] = (void*) sys_wait,
	[20] = (void*) sys_time,
	[21] = (void*) sys_gettimeofday
};
