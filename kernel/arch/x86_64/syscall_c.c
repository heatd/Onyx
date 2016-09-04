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
uint32_t SYSCALL_MAX_NUM = 10;
off_t sys_lseek(int fd, off_t offset, int whence)
{
	if (fd > UINT16_MAX)
		return errno = EBADFD, -1;
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[fd] == NULL)
		return errno = EBADFD, -1;
	if(whence == SEEK_CUR)
		ioctx->file_desc[fd]->seek += offset;
	else if(whence == SEEK_SET)
		ioctx->file_desc[fd]->seek = offset;
	else if(whence == SEEK_END)
		ioctx->file_desc[fd]->seek = ioctx->file_desc[fd]->vfs_node->size;
	else
		return errno = EINVAL;
	return ioctx->file_desc[fd]->seek;
}
ssize_t sys_write(int fd, const void *buf, size_t count)
{
	if(fd == 1)
		tty_write(buf, count);
	return count;
}
/*void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{

}*/
ssize_t sys_read(int fd, const void *buf, size_t count)
{
	ioctx_t *ioctx = &current_process->ctx;
	if( fd > UINT16_MAX)
		return errno = EBADFD;
	if(ioctx->file_desc[fd] == NULL)
		return errno = EBADFD;
	if(!buf)
		return errno = EBADFD;
	ssize_t size = read_vfs(ioctx->file_desc[fd]->seek, count, (char*)buf, ioctx->file_desc[fd]->vfs_node);
	ioctx->file_desc[fd]->seek += size;
	return size;
}
uint64_t sys_getpid()
{
	return current_process->pid;
}
int sys_open(const char *filename, int flags)
{
	ioctx_t *ioctx = &current_process->ctx;
	for(int i = 0; i < UINT16_MAX; i++)
	{
		if(ioctx->file_desc[i] == NULL)
		{
			ioctx->file_desc[i] = malloc(sizeof(file_desc_t));
			memset(ioctx->file_desc[i], 0, sizeof(file_desc_t));
			ioctx->file_desc[i]->vfs_node = open_vfs(fs_root, filename);
			ioctx->file_desc[i]->vfs_node->refcount++;
			ioctx->file_desc[i]->seek = 0;
			ioctx->file_desc[i]->flags = flags;
			return i;
		}
	}
	return errno = EMFILE;
}
int sys_close(int fd)
{
	if(fd > UINT16_MAX) return errno = EBADFD;
	ioctx_t *ioctx = &current_process->ctx;	
	if(ioctx->file_desc[fd] == NULL) return errno = EBADFD;
	close_vfs(ioctx->file_desc[fd]->vfs_node);
	ioctx->file_desc[fd]->vfs_node->refcount--;
	if(ioctx->file_desc[fd]->vfs_node->refcount == 0)
	{
		free(ioctx->file_desc[fd]->vfs_node);
		free(ioctx->file_desc[fd]);
	}
	return 0;
}
int sys_dup(int fd)
{
	if(fd > UINT16_MAX)
		return errno = EBADFD;
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[fd] == NULL)
		return errno = EBADFD;
	for(int i = 0; i < UINT16_MAX; i++)
	{
		if(ioctx->file_desc[i] == NULL)
		{
			ioctx->file_desc[i] = ioctx->file_desc[fd];
			ioctx->file_desc[fd]->vfs_node->refcount++;
			return i;
		}
	}
	return errno = EMFILE;
}
int sys_dup2(int oldfd, int newfd)
{
	if(oldfd > UINT16_MAX)
		return errno = EBADFD;
	if(newfd > UINT16_MAX)
		return errno = EBADFD;
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[oldfd] == NULL)
		return errno = EBADFD;
	if(ioctx->file_desc[newfd])
		sys_close(newfd);
	ioctx->file_desc[newfd] = ioctx->file_desc[oldfd];
	ioctx->file_desc[newfd]->vfs_node->refcount++;
	return newfd;
}
void sys__exit(int status)
{
	sched_destroy_thread(get_current_thread());
	asm volatile("sti");
	while(1) asm volatile("hlt");
}
int sys_posix_spawn(pid_t *pid, const char *path)
{
	process_t *new_proc = process_create(path, &current_process->ctx, current_process);
	*pid = new_proc->pid;
	if(!new_proc)
		panic("OOM while creating process");
	vfsnode_t *in = open_vfs(fs_root, path);

	if (!in)
	{
		printf("%s: No such file or directory\n", path);
		return errno = ENOENT;
	}
	
	char *buffer = malloc(in->size);
	if (!buffer)
		return errno = ENOMEM;
	size_t read = read_vfs(0, in->size, buffer, in);
	if (read != in->size)
		return errno = EAGAIN;
	vmm_entry_t *areas;
	PML4 *new_pt = vmm_clone_as(&areas);
	asm volatile ("mov %0, %%cr3" :: "r"(new_pt)); /* We can't use paging_load_cr3 because that would change current_pml4
							* which we will need for later 
							*/
	void *entry = elf_load((void *) buffer);
	process_create_thread(new_proc, (ThreadCallback) entry, 0, 0, NULL);
	new_proc->cr3 = new_pt;
	vmm_stop_spawning();
	extern PML4 *current_pml4;
	asm volatile("mov %0, %%cr3"::"r"(current_pml4));
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
	[7] = (void*) sys_getpid,
	[8] = (void*) sys_lseek,
	[9] = (void*) sys__exit,
	[10] = (void*) sys_posix_spawn,
};
