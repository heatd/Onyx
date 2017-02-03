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
#include <dirent.h>
#include <mbr.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <sys/uio.h>
#include <sys/utsname.h>

#include <kernel/modules.h>
#include <kernel/network.h>
#include <kernel/kernelinfo.h>
#include <kernel/tty.h>
#include <kernel/process.h>
#include <kernel/vmm.h>
#include <kernel/elf.h>
#include <kernel/panic.h>
#include <kernel/power_management.h>
#include <kernel/cpu.h>

#include <drivers/rtc.h>

#define DEBUG_SYSCALL 1
#undef DEBUG_SYSCALL

#ifdef DEBUG_SYSCALL
#define DEBUG_PRINT_SYSTEMCALL() printf("%s: syscall\n", __func__)
#else
#define DEBUG_PRINT_SYSTEMCALL() asm volatile("nop")
#endif
inline int validate_fd(int fd)
{
	if(fd > UINT16_MAX)
	{
		printf("fd %d is invalid\n", fd);
		return errno =-EBADF;
	}
	ioctx_t *ctx = &current_process->ctx;
	if(ctx->file_desc[fd] == NULL)
	{
		printf("fd %d is invalid\n", fd);
		return errno =-EBADF;
	}
	return 0;
}
const int SYSCALL_MAX_NUM = 46;
off_t sys_lseek(int fd, off_t offset, int whence)
{
	DEBUG_PRINT_SYSTEMCALL();
	#ifdef DEBUG_SYSCALL
		printf("fd %u, off %u, whence %u\n", fd, offset, whence);
	#endif
	if (fd > UINT16_MAX)
	{
		return errno =-EBADF;
	}
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[fd] == NULL)
	{
		return errno =-EBADF;
	}
	if(whence == SEEK_CUR)
		ioctx->file_desc[fd]->seek += offset;
	else if(whence == SEEK_SET)
		ioctx->file_desc[fd]->seek = offset;
	else if(whence == SEEK_END)
		ioctx->file_desc[fd]->seek = ioctx->file_desc[fd]->vfs_node->size;
	else
	{
		return errno =-EINVAL;
	}
	return ioctx->file_desc[fd]->seek;
}
ssize_t sys_write(int fd, const void *buf, size_t count)
{
	if(vmm_check_pointer((void*) buf, count) < 0)
		return errno =-EINVAL;
	DEBUG_PRINT_SYSTEMCALL();
	if(validate_fd(fd))
		return errno =-EBADF;
	if(!current_process->ctx.file_desc[fd]->flags & O_WRONLY)
		return errno =-EROFS;
	write_vfs(current_process->ctx.file_desc[fd]->seek, count, (void*) buf, current_process->ctx.file_desc[fd]->vfs_node);
	return count;
}
void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	DEBUG_PRINT_SYSTEMCALL();
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
	if(!mapping_addr)
		return errno =-ENOMEM, NULL;
	if(!vmm_map_range(mapping_addr, pages, vm_prot))
		return errno =-ENOMEM, NULL;
	return mapping_addr;
}
int sys_munmap(void *addr, size_t length)
{
	DEBUG_PRINT_SYSTEMCALL();

	if ((uintptr_t) addr >= VM_HIGHER_HALF)
		return errno =-EINVAL;
	size_t pages = length / PAGE_SIZE;
	if(length % PAGE_SIZE)
		pages++;
	if(!((uintptr_t) addr & 0xFFFFFFFFFFFFF000))
		return errno =-EINVAL;
	if(!vmm_is_mapped(addr))
		return errno =-EINVAL;
	vmm_unmap_range(addr, pages);
	vmm_destroy_mappings(addr, pages);
	return 0;
}
int sys_mprotect(void *addr, size_t len, int prot)
{
	DEBUG_PRINT_SYSTEMCALL();

	if(!vmm_is_mapped(addr))
		return errno =-EINVAL;
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
ssize_t sys_read(int fd, const void *buf, size_t count)
{
	if(vmm_check_pointer((void*) buf, count) < 0)
		return errno =-EINVAL;
	DEBUG_PRINT_SYSTEMCALL();

	ioctx_t *ioctx = &current_process->ctx;
	if( fd > UINT16_MAX)
	{
		return errno =-EBADF;
	}
	if(ioctx->file_desc[fd] == NULL)
	{
		return errno =-EBADF;
	}
	if(!buf)
	{
		return errno =-EINVAL;
	}
	if(!ioctx->file_desc[fd]->flags & O_RDONLY)
		return errno =-EBADF;
	ssize_t size = read_vfs(ioctx->file_desc[fd]->seek, count, (char*)buf, ioctx->file_desc[fd]->vfs_node);
	ioctx->file_desc[fd]->seek += size;
	return size;
}
int sys_open(const char *filename, int flags)
{
	DEBUG_PRINT_SYSTEMCALL();
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
			if(!ioctx->file_desc[i]->vfs_node)
			{
				free(ioctx->file_desc[i]);
				return errno =-ENOENT;
			}
			ioctx->file_desc[i]->vfs_node->refcount++;
			ioctx->file_desc[i]->seek = 0;
			ioctx->file_desc[i]->flags = flags;
			return i;
		}
	}
	return errno =-ENFILE;
}
spinlock_t close_spl;
int sys_close(int fd)
{
	DEBUG_PRINT_SYSTEMCALL();

	acquire_spinlock(&close_spl);
	if(fd > UINT16_MAX) 
	{
		release_spinlock(&close_spl);
		return errno =-EBADF;
	}
	ioctx_t *ioctx = &current_process->ctx;	
	if(ioctx->file_desc[fd] == NULL)
	{
		release_spinlock(&close_spl);
		return errno =-EBADF;
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
	DEBUG_PRINT_SYSTEMCALL();

	acquire_spinlock(&dup_spl);
	if(fd > UINT16_MAX)
	{
		release_spinlock(&dup_spl);
		return errno =-EBADF;
	}
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[fd] == NULL)
	{
		release_spinlock(&dup_spl);
		return errno =-EBADF;
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
	return errno =-EMFILE;
}
spinlock_t dup2_spl;
int sys_dup2(int oldfd, int newfd)
{
	DEBUG_PRINT_SYSTEMCALL();

	acquire_spinlock(&dup2_spl);
	if(oldfd > UINT16_MAX)
	{
		release_spinlock(&dup2_spl);
		return errno =-EBADF;
	}
	if(newfd > UINT16_MAX)
	{
		release_spinlock(&dup2_spl);
		return errno =-EBADF;
	}
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[oldfd] == NULL)
	{
		release_spinlock(&dup2_spl);
		return errno =-EBADF;
	}
	if(ioctx->file_desc[newfd])
		sys_close(newfd);
	ioctx->file_desc[newfd] = ioctx->file_desc[oldfd];
	ioctx->file_desc[newfd]->vfs_node->refcount++;
	release_spinlock(&dup2_spl);
	return newfd;
}
int sys_mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data)
{
	if(!vmm_is_mapped((void*) source))
		return errno =-EINVAL;
	if(!vmm_is_mapped((void*) target))
		return errno =-EINVAL;
	if(!vmm_is_mapped((void*) filesystemtype))
		return errno =-EINVAL;
	if(!vmm_is_mapped((void*) data))
		return errno =-EINVAL;
	DEBUG_PRINT_SYSTEMCALL();

	return 0;
}
uint64_t sys_nosys()
{
	DEBUG_PRINT_SYSTEMCALL();

	return (uint64_t) -1;
}
uint64_t sys_brk(void *addr)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(addr == NULL)
		return (uint64_t) current_process->brk;
	else
		current_process->brk = addr;
	return 0;
}
time_t sys_time(time_t *s)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(vmm_check_pointer(s, sizeof(time_t)) == 0)
		*s = get_posix_time();
	return get_posix_time();
}
int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	DEBUG_PRINT_SYSTEMCALL();
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
void sys_reboot()
{
	DEBUG_PRINT_SYSTEMCALL();
	pm_reboot();
}
void sys_shutdown()
{
	DEBUG_PRINT_SYSTEMCALL();
	pm_shutdown();
}
ssize_t sys_readv(int fd, const struct iovec *vec, int veccnt)
{
	if(vmm_check_pointer((void*) vec, sizeof(struct iovec) * veccnt) < 0)
		return errno =-EINVAL;
	DEBUG_PRINT_SYSTEMCALL();
	if(validate_fd(fd))
		return errno =-EBADF;
	ioctx_t *ctx = &current_process->ctx;
	if(!vec)
		return errno =-EINVAL;
	if(veccnt == 0)
		return 0;
	if(!ctx->file_desc[fd]->flags & O_RDONLY)
		return errno =-EBADF;
	size_t read = 0;
	read_vfs(ctx->file_desc[fd]->seek, vec[0].iov_len, vec[0].iov_base, ctx->file_desc[fd]->vfs_node);
	for(int i = 0; i < veccnt; i++)
	{
		read_vfs(ctx->file_desc[fd]->seek, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
		read += vec[i].iov_len;
	}
	return read;
}
ssize_t sys_writev(int fd, const struct iovec *vec, int veccnt)
{
	if(vmm_check_pointer((void*) vec, sizeof(struct iovec) * veccnt) < 0)
		return errno =-EINVAL;
	
	DEBUG_PRINT_SYSTEMCALL();
	size_t wrote = 0;
	if(validate_fd(fd))
		return -1;
	ioctx_t *ctx = &current_process->ctx;
	if(!vec)
		return errno =-EINVAL;
	if(veccnt == 0)
		return 0;
	if(!ctx->file_desc[fd]->flags & O_WRONLY)
		return errno =-EROFS;
	for(int i = 0; i < veccnt; i++)
	{
		write_vfs(ctx->file_desc[fd]->seek, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
		wrote += vec[i].iov_len;
	}
	return wrote;
}
ssize_t sys_preadv(int fd, const struct iovec *vec, int veccnt, off_t offset)
{
	if(vmm_check_pointer((void*) vec, sizeof(struct iovec) * veccnt) < 0)
		return errno =-EINVAL;
	
	DEBUG_PRINT_SYSTEMCALL();
	/*if(validate_fd(fd))
		return -1;*/
	ioctx_t *ctx = &current_process->ctx;
	if(!vec)
		return errno =-EINVAL;
	if(veccnt == 0)
		return 0;
	if(!ctx->file_desc[fd]->flags & O_RDONLY)
		return errno =-EBADF;
	size_t read = 0;
	for(int i = 0; i < veccnt; i++)
	{
		read_vfs(offset, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
		read += vec[i].iov_len;
	}
	return read;
}
ssize_t sys_pwritev(int fd, const struct iovec *vec, int veccnt, off_t offset)
{
	if(vmm_check_pointer((void*) vec, sizeof(struct iovec) * veccnt) < 0)
		return errno =-EINVAL;
	DEBUG_PRINT_SYSTEMCALL();
	if(validate_fd(fd))
		return -1;
	ioctx_t *ctx = &current_process->ctx;
	if(veccnt == 0)
		return 0;
	if(!ctx->file_desc[fd]->flags & O_WRONLY)
		return errno =-EROFS;
	size_t wrote = 0;
	for(int i = 0; i < veccnt; i++)
	{
		write_vfs(offset, vec[i].iov_len, vec[i].iov_base, ctx->file_desc[fd]->vfs_node);
		wrote += vec[i].iov_len;
	}
	return wrote;
}
int sys_getdents(int fd, struct dirent *dirp, unsigned int count)
{
	if(vmm_check_pointer((void*) dirp, sizeof(struct dirent) * count) < 0)
		return errno =-EINVAL;
	if(validate_fd(fd))
		return errno =-EBADF;
	if(!count)
		return 0;
	ioctx_t *ctx = &current_process->ctx;
	int read_entries_size = getdents_vfs(count, dirp, ctx->file_desc[fd]->vfs_node);
	return read_entries_size;
}
int sys_ioctl(int fd, int request, va_list args)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(validate_fd(fd))
		return errno =-EBADF;
	ioctx_t *ctx = &current_process->ctx;
	return ioctl_vfs(request, args, ctx->file_desc[fd]->vfs_node);
}
int sys_kill(pid_t pid, int sig)
{
	DEBUG_PRINT_SYSTEMCALL();

	process_t *p = NULL;
	if((int)pid > 0)
	{
		if(pid == current_process->pid)
		{
			p = current_process;
		}
		else
			p = get_process_from_pid(pid);
		if(!p)
			return errno =-ESRCH;	
	}
	if(sig == 0)
		return 0;
	if(sig > 26)
		return errno =-EINVAL;
	if(sig < 0)
		return errno =-EINVAL;
	current_process->signal_pending = 1;
	current_process->sinfo.signum = sig;
	current_process->sinfo.handler = current_process->sighandlers[sig];
	return 0;
}
int sys_truncate(const char *path, off_t length)
{
	return errno =-ENOSYS;
}
int sys_ftruncate(int fd, off_t length)
{
	if(validate_fd(fd))
		return errno =-EBADF;
	return errno =-ENOSYS; 
}
int sys_personality(unsigned long val)
{
	DEBUG_PRINT_SYSTEMCALL();
	// TODO: Use this syscall for something. This might be potentially very useful
	current_process->personality = val;
	return 0;
}
int sys_setuid(uid_t uid)
{
	DEBUG_PRINT_SYSTEMCALL();

	if(uid == 0 && current_process->uid != 0)
		return errno =-EPERM;
	current_process->setuid = uid;
	return 0;
}
int sys_setgid(gid_t gid)
{
	DEBUG_PRINT_SYSTEMCALL();
	
	current_process->setgid = gid;
	return 0;
}
int sys_isatty(int fd)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(fd < 3)
		return 1;
	if(validate_fd(fd))
		return errno =-EBADF;
	ioctx_t *ioctx = &current_process->ctx;
	if(ioctx->file_desc[fd]->vfs_node->type & VFS_TYPE_CHAR_DEVICE)
		return 1;
	else
		return errno =-ENOTTY, 0;
}
sighandler_t sys_signal(int signum, sighandler_t handler)
{
	DEBUG_PRINT_SYSTEMCALL();
	process_t *proc = current_process;
	if(!proc)
		return (sighandler_t) SIG_ERR;
	if(signum > 26)
		return (sighandler_t) SIG_ERR;
	if(signum < 0)
		return (sighandler_t) SIG_ERR;
	if(!vmm_is_mapped(handler))
		return (sighandler_t) SIG_ERR;
	if(handler == (sighandler_t) SIG_IGN)
	{
		/* SIGKILL, SIGSEGV and SIGSTOP can't be masked (yes, I'm also enforcing SIGSEGV to be on(non-standard)*/
		switch(signum)
		{
			case SIGKILL:
			case SIGSEGV:
			case SIGSTOP:
				return (sighandler_t) SIG_ERR;
		}
	}
	sighandler_t ret = proc->sighandlers[signum];
	proc->sighandlers[signum] = handler;

	return ret;
}
extern void __sigret_return(uintptr_t stack);
void sys_sigreturn(void *ret)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(ret == (void*) -1 && current_process->signal_pending)
	{
		/* Switch the registers again */
		memcpy(get_current_thread()->kernel_stack, &current_process->old_regs, sizeof(registers_t));
		current_process->signal_pending = 0;
		current_process->signal_dispatched = 0;
		__sigret_return((uintptr_t) get_current_thread()->kernel_stack);
		__builtin_unreachable();
	}
	if(!vmm_is_mapped(ret))
		return;
	current_process->sigreturn = ret;
}
int sys_insmod(const char *path, const char *name)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(!vmm_is_mapped((void*) path))
		return errno =-EFAULT;
	if(!vmm_is_mapped((void*) name))
		return errno =-EFAULT;
	/* All the work is done by load_module; A return value of 1 means -1 for user-space, while -0 still = 0 */
	return -load_module(path, name);
}
int sys_uname(struct utsname *buf)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(vmm_check_pointer(buf, sizeof(struct utsname)) < 0)
		return errno =-EFAULT;
	strcpy(buf->sysname, OS_NAME);
	strcpy(buf->release, OS_RELEASE);
	strcpy(buf->version, OS_VERSION);
	strcpy(buf->machine, OS_MACHINE);

	strcpy(buf->nodename, network_gethostname());
	
	return 0;
}
int sys_sethostname(const void *name, size_t len)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(len > _UTSNAME_LENGTH)
		return errno =-EINVAL;
	if(vmm_check_pointer((void *) name, len) < 0)
		return errno =-EFAULT;
	if((ssize_t) len < 0)
		return errno =-EINVAL;
	/* We need to copy the name, since the user pointer isn't safe */
	char *hostname = malloc(len+1);
	if(!name)
		return errno =-ENOMEM;
	memset(hostname, 0, len+1);
	memcpy(hostname, name, len);
	network_sethostname(hostname);
	
	return 0;
}
int sys_gethostname(char *name, size_t len)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(vmm_check_pointer(name, len) < 0)
		return errno =-EFAULT;
	if((ssize_t) len < 0)
		return errno =-EINVAL;
	
	size_t str_len = strlen(network_gethostname());
	if(len < str_len)
		return errno =-EINVAL;
	strcpy(name, network_gethostname());
	
	return 0;
}
extern void *phys_fb;
void *sys_mapfb()
{
	void *mapping_addr = vmm_allocate_virt_address(0, 1024, VMM_TYPE_REGULAR, VMM_USER | VMM_WRITE);
	uintptr_t temp = (uintptr_t) mapping_addr, temp2 = (uintptr_t) phys_fb; 
	for(int i = 0; i < 1024; i++)
	{
		paging_map_phys_to_virt(temp, temp2, VMM_WRITE | VMM_USER);
		temp += 4096;
		temp2 += 4096;
	}
	return mapping_addr;
}
int sys_nanosleep(const struct timespec *req, struct timespec *rem)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(vmm_check_pointer((void*) req, sizeof(struct timespec)) < 0)
		return errno =-EFAULT;
	time_t ticks = req->tv_sec * 1000;
	if(req->tv_nsec)
	{
		if(req->tv_nsec < 500)
			ticks++;
	}
	sched_sleep(ticks);
	return 0;
}
void syscall_helper(int syscall_num)
{
	printf("Syscall invoked!\nNumber: %u\n", syscall_num);
}
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
int sys_arch_prctl(int code, unsigned long *addr)
{
	DEBUG_PRINT_SYSTEMCALL();
	if(code == ARCH_SET_FS)
	{
		current_process->fs = (unsigned long) addr;
		wrmsr(FS_BASE_MSR, (uintptr_t)current_process->fs & 0xFFFFFFFF, (uintptr_t)current_process->fs >> 32);
	}
	else if(code == ARCH_GET_FS)
	{
		if(!vmm_is_mapped(addr))
			return errno =-EINVAL;
		*addr = (unsigned long) current_process->fs;
	}
	return 0;
}
pid_t sys_set_tid_address(pid_t *tidptr)
{
	DEBUG_PRINT_SYSTEMCALL();
	return get_current_thread()->id;
}
void sys_badsys()
{
	printf("Non-implemented syscall invoked!\n");
}

extern void sys__exit();
extern void sys_fork();
extern void sys_getppid();
extern void sys_getpid();
extern void sys_execve();
extern void sys_wait();
extern int sys_syslog(int type, char *buffer, int len);
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
	[9] = (void*) sys_nosys,
	[10] = (void*) sys_fork,
	[11] = (void*) sys_mmap,
	[12] = (void*) sys_munmap,
	[13] = (void*) sys_mprotect,
	[14] = (void*) sys_mount,
	[15] = (void*) sys_execve,
	[16] = (void*) sys_brk,
	[17] = (void*) sys_kill,
	[18] = (void*) sys_getppid,
	[19] = (void*) sys_wait,
	[20] = (void*) sys_time,
	[21] = (void*) sys_gettimeofday,
	[22] = (void*) sys_reboot,
	[23] = (void*) sys_shutdown,
	[24] = (void*) sys_readv,
	[25] = (void*) sys_writev,
	[26] = (void*) sys_preadv,
	[27] = (void*) sys_pwritev,
	[28] = (void*) sys_getdents,
	[29] = (void*) sys_ioctl,
	[30] = (void*) sys_truncate,
	[31] = (void*) sys_ftruncate,
	[32] = (void*) sys_personality,
	[33] = (void*) sys_setuid,
	[34] = (void*) sys_setgid,
	[35] = (void*) sys_isatty,
	[36] = (void*) sys_signal,
	[37] = (void*) sys_sigreturn,
	[38] = (void*) sys_insmod,
	[39] = (void*) sys_uname,
	[40] = (void*) sys_gethostname,
	[41] = (void*) sys_sethostname,
	[42] = (void*) sys_mapfb,
	[43] = (void*) sys_nanosleep,
	[44] = (void*) sys_arch_prctl,
	[45] = (void*) sys_set_tid_address,
	[46] = (void*) sys_syslog,
	[255] = (void*) sys_badsys
};
