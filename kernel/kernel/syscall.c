/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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
#include <sys/resource.h>
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
#include <kernel/page.h>

const uint64_t SYSCALL_MAX_NUM = 68;

uint64_t sys_nosys()
{
	return (uint64_t) -1;
}

extern void sys_exit();
extern void sys_fork();
extern void sys_getppid();
extern void sys_getpid();
extern void sys_execve();
extern pid_t sys_wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage);
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
extern int sys_kill(pid_t pid, int sig);
extern int sys_personality(unsigned long val);
extern int sys_setuid(uid_t uid);
extern int sys_setgid(gid_t gid);
extern int sys_fcntl(int fd, int cmd, ...);
extern int sys_stat(const char *pathname, struct stat *buf);
extern int sys_fstat(int fd, struct stat *buf);
extern int sys_clock_gettime(clockid_t clk_id, struct timespec *tp);
extern int sys_pipe(int *pipefd);
extern int sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
extern int sys_memstat(struct memstat *memstat);
extern int sys_chdir(const char *path);
extern int sys_fchdir(int fildes);
extern int sys_getcwd(char *path, size_t size);
extern uid_t sys_getuid(void);
extern gid_t sys_getgid(void);
extern int sys_openat(int dirfd, const char *path, int flags, mode_t mode);
extern int sys_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
extern int sys_fmount(int fd, const char *path);
extern int sys_clone(int (*fn)(void *), void *child_stack, int flags, void *arg, pid_t *ptid, void *tls);
extern void sys_exit_thread(int value);
extern int sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
extern int sys_sigsuspend(const sigset_t *set);
extern int sys_pause(void);
extern int sys_futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int *uaddr2, int val3);
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
	[8] = (void*) sys_exit,
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
	[19] = (void*) sys_wait4,
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
	[36] = (void*) sys_nosys, /* FREE */
	[37] = (void*) sys_sigreturn,
	[38] = (void*) sys_insmod,
	[39] = (void*) sys_uname,
	[40] = (void*) sys_gethostname,
	[41] = (void*) sys_sethostname,
	[42] = (void*) sys_clock_gettime,
	[43] = (void*) sys_nanosleep,
	[44] = (void*) sys_arch_prctl,
	[45] = (void*) sys_set_tid_address,
	[46] = (void*) sys_syslog,
	[47] = (void*) sys_fcntl,
	[48] = (void*) sys_nosys, /* Reserved for sync */
	[49] = (void*) sys_stat,
	[50] = (void*) sys_fstat,
	[51] = (void*) sys_nosys, /* Reserved for lstat */
	[52] = (void*) sys_sigaction,
	[53] = (void*) sys_pipe,
	[54] = (void*) sys_memstat,
	[55] = (void*) sys_chdir,
	[56] = (void*) sys_fchdir,
	[57] = (void*) sys_getcwd,
	[58] = (void*) sys_getuid,
	[59] = (void*) sys_getgid,
	[60] = (void*) sys_openat,
	[61] = (void*) sys_fstatat,
	[62] = (void*) sys_fmount,
	[63] = (void*) sys_clone,
	[64] = (void*) sys_exit_thread,
	[65] = (void*) sys_sigprocmask,
	[66] = (void*) sys_sigsuspend,
	[67] = (void*) sys_pause,
	[68] = (void*) sys_futex,
	[255] = (void*) sys_nosys
};
