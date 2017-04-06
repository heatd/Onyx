/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
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

const int SYSCALL_MAX_NUM = 46;

uint64_t sys_nosys()
{
	return (uint64_t) -1;
}

extern void sys__exit();
extern void sys_fork();
extern void sys_getppid();
extern void sys_getpid();
extern void sys_execve();
extern void sys_wait();
extern ssize_t sys_read(int fd, const void *buf, size_t count);
extern int sys_open(const char *filename, int flags);
extern int sys_close(int fd);
extern int sys_dup(int fd);
extern int sys_dup2(int oldfd, int newfd);
extern ssize_t sys_readv(int fd, const struct iovec *vec, int veccnt);
extern ssize_t sys_writev(int fd, const struct iovec *vec, int veccnt);
extern ssize_t sys_preadv(int fd, const struct iovec *vec, int veccnt, off_t offset);
extern ssize_t sys_pwritev(int fd, const struct iovec *vec, int veccnt, off_t offset);
extern int sys_getdents(int fd, struct dirent *dirp, unsigned int count);
extern int sys_ioctl(int fd, int request, va_list args);
extern int sys_truncate(const char *path, off_t length);
extern int sys_ftruncate(int fd, off_t length);
extern off_t sys_lseek(int fd, off_t offset, int whence);
extern int sys_mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data);
extern ssize_t sys_write(int fd, const void *buf, size_t count);
extern int sys_isatty(int fd);
extern int sys_syslog(int type, char *buffer, int len);
extern void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
extern int sys_munmap(void *addr, size_t length);
extern int sys_mprotect(void *addr, size_t len, int prot);
extern uint64_t sys_brk(void *addr);
extern time_t sys_time(time_t *s);
extern int sys_gettimeofday(struct timeval *tv, struct timezone *tz);
extern int sys_arch_prctl(int code, unsigned long *addr);
extern pid_t sys_set_tid_address(pid_t *tidptr);
extern int sys_nanosleep(const struct timespec *req, struct timespec *rem);
extern int sys_sethostname(const void *name, size_t len);
extern int sys_gethostname(char *name, size_t len);
extern int sys_uname(struct utsname *buf);
extern void sys_reboot();
extern void sys_shutdown();
extern int sys_insmod(const char *path, const char *name);
extern void sys_sigreturn(void *ret);
extern sighandler_t sys_signal(int signum, sighandler_t handler);
extern int sys_kill(pid_t pid, int sig);
extern int sys_personality(unsigned long val);
extern int sys_setuid(uid_t uid);
extern int sys_setgid(gid_t gid);
extern int sys_fcntl(int fd, int cmd, ...);
int sys_stat(const char *pathname, struct stat *buf);
int sys_fstat(int fd, struct stat *buf);
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
	[42] = (void*) sys_nosys, /* needs to be filled with another system call (was a redundent one) */
	[43] = (void*) sys_nanosleep,
	[44] = (void*) sys_arch_prctl,
	[45] = (void*) sys_set_tid_address,
	[46] = (void*) sys_syslog,
	[47] = (void*) sys_fcntl,
	[49] = (void*) sys_stat,
	[50] = (void*) sys_fstat,
	[255] = (void*) sys_nosys
};
