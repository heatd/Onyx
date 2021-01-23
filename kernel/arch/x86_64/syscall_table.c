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
#include <sys/times.h>

#include <onyx/modules.h>
#include <onyx/kernelinfo.h>
#include <onyx/tty.h>
#include <onyx/process.h>
#include <onyx/vm.h>
#include <onyx/elf.h>
#include <onyx/panic.h>
#include <onyx/power_management.h>
#include <onyx/cpu.h>
#include <onyx/page.h>
#include <onyx/poll.h>

uint64_t sys_nosys(void)
{
	return (uint64_t) -ENOSYS;
}

extern void sys_exit();
extern void sys_fork();
extern void sys_getppid();
extern void sys_getpid();
extern void sys_execve();
extern pid_t sys_wait4(pid_t pid, int *wstatus, int options,
struct rusage *rusage);
extern ssize_t sys_read(int fd, const void *buf, size_t count);
extern int sys_open(const char *filename, int flags, mode_t mode);
extern int sys_close(int fd);
extern int sys_dup(int fd);
extern int sys_dup2(int oldfd, int newfd);
extern ssize_t sys_readv(int fd, const struct iovec *vec, int veccnt);
extern ssize_t sys_writev(int fd, const struct iovec *vec, int veccnt);
extern ssize_t sys_preadv(int fd, const struct iovec *vec, int veccnt,
off_t offset);
extern ssize_t sys_pwritev(int fd, const struct iovec *vec, int veccnt,
off_t offset);
extern int sys_getdents(int fd, struct dirent *dirp, unsigned int count);
extern int sys_ioctl(int fd, int request, va_list args);
extern int sys_truncate(const char *path, off_t length);
extern int sys_ftruncate(int fd, off_t length);
extern off_t sys_lseek(int fd, off_t offset, int whence);
extern int sys_mount(const char *source, const char *target,
const char *filesystemtype, unsigned long mountflags, const void *data);
extern ssize_t sys_write(int fd, const void *buf, size_t count);
extern int sys_syslog(int type, char *buffer, int len);
extern void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd,
 off_t offset);
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
extern int sys_set_power_state(unsigned int state, unsigned int flags);
extern int sys_shutdown(int sockfd, int how);
extern int sys_insmod(const char *path, const char *name);
extern void sys_sigreturn(void *ret);
extern int sys_kill(pid_t pid, int sig);
extern int sys_personality(unsigned long val);
extern int sys_setuid(uid_t uid);
extern int sys_setgid(gid_t gid);
extern int sys_fcntl(int fd, int cmd, unsigned long arg);
extern int sys_stat(const char *pathname, struct stat *buf);
extern int sys_lstat(const char *pathname, struct stat *buf);
extern int sys_fstat(int fd, struct stat *buf);
extern int sys_clock_gettime(clockid_t clk_id, struct timespec *tp);
extern int sys_pipe(int *pipefd);
extern int sys_sigaction(int signum, const struct k_sigaction *act,
struct k_sigaction *oldact);
extern int sys_memstat(struct memstat *memstat);
extern int sys_chdir(const char *path);
extern int sys_fchdir(int fildes);
extern int sys_getcwd(char *path, size_t size);
extern uid_t sys_getuid(void);
extern gid_t sys_getgid(void);
extern int sys_openat(int dirfd, const char *path, int flags, mode_t mode);
extern int sys_fstatat(int dirfd, const char *pathname, struct stat *buf,
int flags);
extern int sys_fmount(int fd, const char *path);

struct tid_out;
int sys_clone(int (*fn)(void *), void *child_stack, int flags, void *arg, struct tid_out *out, void *tls);
extern void sys_exit_thread(int value);
extern int sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
extern int sys_sigsuspend(const sigset_t *set);
extern int sys_pause(void);
extern int sys_futex(int *uaddr, int futex_op, int val,
const struct timespec *timeout, int *uaddr2, int val3);
extern int sys_getrandom(void *buf, size_t buflen, unsigned int flags);
extern int sys_socket(int domain, int type, int protocol);
extern ssize_t sys_sendto(int sockfd, const void *buf, size_t len, int flags,
	struct sockaddr *addr, socklen_t addrlen);
extern int sys_connect(int sockfd, const struct sockaddr *addr,
socklen_t addrlen);
extern int sys_bind(int sockfd, const struct sockaddr *addr,
socklen_t addrlen);
extern clock_t sys_times(struct tms *buf);
extern int sys_getrusage(int who, struct rusage *usage);
extern long sys_ptrace(long request, pid_t pid, void *addr, void *data,
void *addr2);
extern ssize_t sys_recvfrom(int sockfd, void *buf, size_t len, int flags,
struct sockaddr *src_addr, socklen_t *addrlen);
extern int sys_proc_event_attach(pid_t pid, unsigned long flags);
extern int sys_access(const char *path, int amode);
extern void *sys_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address);
extern int sys_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
                     const sigset_t *sigmask, size_t sigsetsize);
extern int sys_fallocate(int fd, int mode, off_t offset, off_t len);
extern pid_t sys_gettid(void);
int sys_mkdirat(int dirfd, const char *upath, mode_t mode);
int sys_mkdir(const char *upath, mode_t mode);
int sys_rmdir(const char *pathname);
int sys_mknod(const char *pathname, mode_t mode, dev_t dev);
int sys_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
int sys_link(const char *oldpath, const char *newpath);
int sys_linkat(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath, int flags);
int sys_unlink(const char *pathname);
int sys_unlinkat(int dirfd, const char *pathname, int flags);
int sys_symlink(const char *target, const char *linkpath);
int sys_symlinkat(const char *target, int newdirfd, const char *linkpath);
ssize_t sys_readlink(const char *pathname, char *buf, size_t bufsiz);
ssize_t sys_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
int sys_chmod(const char *pathname, mode_t mode);
int sys_fchmod(int fd, mode_t mode);
int sys_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
int sys_chown(const char *pathname, uid_t owner, gid_t group);
int sys_fchown(int fd, uid_t owner, gid_t group);
int sys_lchown(const char *pathname, uid_t owner, gid_t group);
int sys_fchownat(int dirfd, const char *pathname,
                    uid_t owner, gid_t group, int flags);
mode_t sys_umask(mode_t mask);
int sys_rename(const char *oldpath, const char *newpath);
int sys_renameat(int olddirfd, const char *oldpath,
                    int newdirfd, const char *newpath);
int sys_utimensat(int dirfd, const char *pathname,
                     const struct timespec *times, int flags);
int sys_faccessat(int dirfd, const char *pathname, int mode, int flags);
int sys_listen(int sockfd, int backlog);
int sys_accept(int sockfd, struct sockaddr *addr, socklen_t *slen);
int sys_accept4(int sockfd, struct sockaddr *addr, socklen_t *slen, int flags);
int sys_rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info);
int sys_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info);
int sys_tkill(int tid, int sig);
int sys_tgkill(int pid, int tid, int sig);
int sys_rt_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout, size_t sigsetlen);
int sys_rt_sigpending(sigset_t *set, size_t sigsetlen);
int sys_sigaltstack(const stack_t *new_stack, stack_t *old_stack, const struct syscall_frame *frame);
int sys_setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);
int sys_getitimer(int which, struct itimerval *curr_value);
ssize_t sys_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t sys_pwrite(int fd, const void *buf, size_t count, off_t offset);
int sys_fsync(int fd);
void sys_sync(void);

int sys_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int sys_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
ssize_t sys_sendmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags);
pid_t sys_getpgid(pid_t pid);
int sys_setpgid(pid_t pid, pid_t pgid);
int sys_dup3(int oldfd, int newfd, int flags);
int sys_get_uids(uid_t *ruid, uid_t *euid, uid_t *suid);
int sys_get_gids(gid_t *rgid, gid_t *egid, gid_t *sgid);
int sys_set_uids(unsigned int flags, uid_t ruid, uid_t euid, uid_t suid);
int sys_set_gids(unsigned int flags, gid_t rgid, gid_t egid, gid_t sgid);
int sys_setgroups(size_t size, const gid_t *ugids);
int sys_getgroups(int size, gid_t *ugids);

void *syscall_table_64[] =
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
	[22] = (void*) sys_set_power_state,
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
	[35] = (void*) sys_nosys,
	[36] = (void*) sys_mremap,
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
	[48] = (void*) sys_sync,
	[49] = (void*) sys_stat,
	[50] = (void*) sys_fstat,
	[51] = (void*) sys_lstat,
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
	[69] = (void*) sys_getrandom,
	[70] = (void*) sys_socket,
	[71] = (void*) sys_sendto,
	[72] = (void*) sys_bind,
	[73] = (void*) sys_connect,
	[74] = (void*) sys_recvfrom,
	[75] = (void*) sys_times,
	[76] = (void*) sys_getrusage,
	[77] = (void*) sys_ptrace,
	[78] = (void*) sys_ppoll,
	[79] = (void*) sys_pselect,
	[80] = (void*) sys_proc_event_attach,
	[81] = (void*) sys_access,
	[82] = (void*) sys_fallocate,
	[83] = (void*) sys_gettid,
	[84] = (void*) sys_mkdir,
	[85] = (void*) sys_rmdir,
	[86] = (void*) sys_mknod,
	[87] = (void*) sys_link,
	[88] = (void*) sys_unlink,
	[89] = (void*) sys_symlink,
	[90] = (void*) sys_readlink,
	[91] = (void*) sys_chmod,
	[92] = (void*) sys_fchmod,
	[93] = (void*) sys_chown,
	[94] = (void*) sys_fchown,
	[95] = (void*) sys_lchown,
	[96] = (void*) sys_umask,
	[97] = (void*) sys_rename,
	[98] = (void*) sys_nosys, // TODO: getrlimit
	[99] = (void*) sys_mkdirat,
	[100] = (void*) sys_mknodat,
	[101] = (void*) sys_fchownat,
	[102] = (void*) sys_utimensat,
	[103] = (void*) sys_unlinkat,
	[104] = (void*) sys_renameat,
	[105] = (void*) sys_linkat,
	[106] = (void*) sys_symlinkat,
	[107] = (void*) sys_readlinkat,
	[108] = (void*) sys_fchmodat,
	[109] = (void*) sys_faccessat,
	[110] = (void*) sys_listen,
	[111] = (void*) sys_accept,
	[112] = (void*) sys_accept4,
	[113] = (void*) sys_rt_sigqueueinfo,
	[114] = (void*) sys_rt_tgsigqueueinfo,
	[115] = (void*) sys_tkill,
	[116] = (void*) sys_tgkill,
	[117] = (void*) sys_rt_sigpending,
	[118] = (void*) sys_rt_sigtimedwait,
	[119] = (void*) sys_setsockopt,
	[120] = (void*) sys_getsockopt,
	[121] = (void*) sys_nosys,
	[122] = (void*) sys_nosys,
	[123] = (void*) sys_sigaltstack,
	[124] = (void*) sys_setitimer,
	[125] = (void*) sys_getitimer,
	[126] = (void*) sys_pread,
	[127] = (void*) sys_pwrite,
	[128] = (void*) sys_fsync,
	[129] = (void*) sys_sendmsg,
	[130] = (void*) sys_recvmsg,
	[131] = (void*) sys_nosys, // sendmmsg
	[132] = (void*) sys_nosys, // recvmmsg
	[133] = (void*) sys_setpgid,
	[134] = (void*) sys_getpgid,
	[135] = (void*) sys_dup3,
	[136] = (void*) sys_get_uids,
	[137] = (void*) sys_get_gids,
	[138] = (void*) sys_set_uids,
	[139] = (void*) sys_set_gids,
	[140] = (void*) sys_setgroups,
	[141] = (void*) sys_getgroups
};
