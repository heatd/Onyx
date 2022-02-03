/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <fcntl.h>
#include <proc_event.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/dir.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "errnos.h"

#define MAX_ARGS 8

/* HACK! */
#define MAX_SYS 500

struct syscall_args
{
    size_t args[MAX_ARGS];
};

struct system_call
{
    const char *name;
    void (*callback)(struct syscall_args *args, struct proc_event *event);
    void (*exit)(size_t return_value, struct proc_event *event);
};

void print_errno(int err)
{
    const char *err_name = NULL;
    if (err >= NUM_ERRNOS)
    {
        err_name = __errno_table[0];
    }
    else
        err_name = __errno_table[err];

    printf("%s", err_name);
}

void do_write(struct syscall_args *args, struct proc_event *event)
{
    printf("%u, %p, %lu", args->args[0], args->args[1], args->args[2]);
}

void do_long_exit(size_t return_value, struct proc_event *event)
{
    ssize_t ret = (ssize_t) return_value;

    if (ret < 0)
    {
        printf("-1 ");
        print_errno((int) -ret);
    }
    else
        printf("%ld", ret);
}

void do_integer_exit(size_t return_value, struct proc_event *event)
{
    int ret = (int) return_value;

    if (ret < 0)
    {
        printf("-1 ");
        print_errno((int) -ret);
    }
    else
        printf("%d", ret);
}

void do_void_exit(size_t return_value, struct proc_event *event)
{
    printf("0");
}

void do_noexit(size_t return_value, struct proc_event *event)
{
    printf("?");
}

void do_pointer_exit(size_t return_value, struct proc_event *event)
{
    printf("%p", (void *) return_value);
}

void do_mmap_exit(size_t return_value, struct proc_event *event)
{
    void *ptr = (void *) return_value;
    if (ptr == MAP_FAILED)
        printf("-1 MAP_FAILED");
    else
        printf("%p", ptr);
}

void do_read(struct syscall_args *args, struct proc_event *event)
{
    printf("%u, %p, %lu", args->args[0], args->args[1], args->args[2]);
}

void do_open(struct syscall_args *args, struct proc_event *event)
{
    printf("%p, %d, %d", args->args[0], args->args[1], args->args[2]);
}

void do_close(struct syscall_args *args, struct proc_event *event)
{
    printf("%u", args->args[0]);
}

void do_dup(struct syscall_args *args, struct proc_event *event)
{
    printf("%d", args->args[0]);
}

void do_dup2(struct syscall_args *args, struct proc_event *event)
{
    printf("%d, %d", args->args[0], args->args[1]);
}

void do_noargs(struct syscall_args *args, struct proc_event *event)
{
    (void) args;
    (void) event;
}

void do_lseek(struct syscall_args *args, struct proc_event *event)
{
    int fd = args->args[0];
    off_t offset = args->args[1];
    int whence = args->args[2];

    const char *whence_str = NULL;

    switch (whence)
    {
    case SEEK_SET:
        whence_str = "SEEK_SET";
        break;
    case SEEK_CUR:
        whence_str = "SEEK_CUR";
        break;
    case SEEK_END:
        whence_str = "SEEK_END";
        break;
    }

    if (whence_str)
        printf("%d, %ld, %s", fd, offset, whence_str);
    else
        printf("%d, %ld, %d", fd, offset, whence);
}

void do_exit(struct syscall_args *args, struct proc_event *event)
{
    printf("%d", args->args[0]);
}

void print_prots(int prot)
{
    if (prot == PROT_NONE)
    {
        printf("PROT_NONE");
    }
    else
    {
        bool do_or = false;
        if (prot & PROT_READ)
        {
            printf("PROT_READ");
            do_or = true;
        }

        if (prot & PROT_WRITE)
        {
            printf(do_or ? "|PROT_WRITE" : "PROT_WRITE");
            do_or = true;
        }

        if (prot & PROT_EXEC)
        {
            printf(do_or ? "|PROT_EXEC" : "PROT_EXEC");
            do_or = true;
        }
    }
}

void do_mmap(struct syscall_args *args, struct proc_event *event)
{
    void *addr = (void *) args->args[0];
    size_t len = args->args[1];
    int prot = (int) args->args[2];
    int flags = (int) args->args[3];
    int fildes = (int) args->args[4];
    off_t off = (off_t) args->args[5];

    printf("%p, %lu, ", addr, len);

    print_prots(prot);
    printf(", ");

    bool do_or = false;
    if (flags & MAP_PRIVATE)
    {
        printf("MAP_PRIVATE");
        do_or = true;
    }

    if (flags & MAP_SHARED)
    {
        printf(do_or ? "|MAP_SHARED" : "MAP_SHARED");
        do_or = true;
    }

    if (flags & MAP_ANONYMOUS)
    {
        printf(do_or ? "|MAP_ANONYMOUS" : "MAP_ANONYMOUS");
        do_or = true;
    }

    if (flags & MAP_FIXED)
    {
        printf(do_or ? "|MAP_FIXED" : "MAP_FIXED");
        do_or = true;
    }

    /* TODO: Add flags as needed */
    printf(", %d, %ld", fildes, off);
}

void do_munmap(struct syscall_args *args, struct proc_event *event)
{
    void *addr = (void *) args->args[0];
    size_t len = args->args[1];
    printf("%p, %lu", addr, len);
}

void do_mprotect(struct syscall_args *args, struct proc_event *event)
{
    int prot = (int) args->args[2];
    /* mprotect and munmap share the same first two arguments */
    do_munmap(args, event);

    printf(", ");
    print_prots(prot);
}

void do_mount(struct syscall_args *args, struct proc_event *event)
{
    /* TODO: Don't bother print string arguments since we can't print them out yet */
}

void do_execve(struct syscall_args *args, struct proc_event *event)
{
    /* Same as above */
    const char *pathname = (const char *) args->args[0];
    char **argv = (char **) args->args[1];
    char **envp = (char **) args->args[2];
    (void) pathname;
    (void) argv;
    (void) envp;
}

void do_brk(struct syscall_args *args, struct proc_event *event)
{
    void *new_brk = (void *) args->args[0];
    printf("%p", new_brk);
}

const char *signal_names[] = {"SIGHUP",  "SIGINT",  "SIGQUIT", "SIGILL",  "SIGABRT",
                              "SIGFPE",  "SIGKILL", "SIGSEGV", "SIGPIPE", "SIGALRM",
                              "SIGTERM", "SIGUSR1", "SIGUSR2", "SIGCHLD", "SIGCONT",
                              "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU"};

const char *get_signame(int sig)
{
    if ((unsigned int) sig >= sizeof(signal_names) / sizeof(const char *))
        return NULL;
    return signal_names[sig - 1];
}

void do_kill(struct syscall_args *args, struct proc_event *event)
{
    pid_t pid = (pid_t) args->args[0];
    int sig = (int) args->args[1];
    const char *s = get_signame(sig);

    if (s)
        printf("%i, %s", pid, s);
    else
        printf("%i, %i", pid, sig);
}

void do_wait4(struct syscall_args *args, struct proc_event *event)
{
    pid_t pid = (pid_t) args->args[0];
    int *wstatus = (int *) args->args[1];
    int options = (int) args->args[2];
    struct rusage *rusage = (struct rusage *) args->args[3];

    printf("%i, %p, ", pid, wstatus);
    bool do_or = false;
    if (options & WNOHANG)
    {
        printf("WNOHANG");
        do_or = true;
    }

    if (options & WUNTRACED)
    {
        printf(do_or ? "|WUNTRACED" : "WUNTRACED");
        do_or = true;
    }

    if (options & WCONTINUED)
    {
        printf(do_or ? "|WCONTINUED" : "WCONTINUED");
    }

    printf(", %p", rusage);
}

void do_time(struct syscall_args *args, struct proc_event *event)
{
    time_t *p = (time_t *) args->args[0];
    printf("%p", p);
}

void do_gettimeofday(struct syscall_args *args, struct proc_event *event)
{
    struct timeval *tv = (struct timeval *) args->args[0];
    struct timezone *tz = (struct timezone *) args->args[1];

    printf("%p, %p", tv, tz);
}

void do_print_iov(struct syscall_args *args, struct proc_event *event)
{
    int fd = (int) args->args[0];
    struct iovec *iov = (struct iovec *) args->args[1];
    int iovec_cnt = (int) args->args[2];
    printf("%i, %p, %i", fd, iov, iovec_cnt);
}

void do_print_piov(struct syscall_args *args, struct proc_event *event)
{
    do_print_iov(args, event);
    printf(", %l", (off_t) args->args[3]);
}

void do_getdents(struct syscall_args *args, struct proc_event *event)
{
    int fd = (int) args->args[0];
    struct dirent *d = (struct dirent *) args->args[1];
    unsigned int count = (unsigned int) args->args[2];

    printf("%i, %p, %u", fd, d, count);
}

void do_ioctl(struct syscall_args *args, struct proc_event *event)
{
    /* TODO: Handle the different ioctl reqs */
    int fd = (int) args->args[0];
    unsigned long req = args->args[1];
    char *argp = (char *) args->args[2];

    printf("%i, %lu, %p", fd, req, argp);
}

void do_truncate(struct syscall_args *args, struct proc_event *event)
{
    const char *path = (const char *) args->args[0];
    off_t len = (off_t) args->args[1];

    printf("%p, %l", path, len);
}

void do_ftruncate(struct syscall_args *args, struct proc_event *event)
{
    int fd = (int) args->args[0];
    off_t len = (off_t) args->args[1];

    printf("%i, %l", fd, len);
}

void do_personality(struct syscall_args *args, struct proc_event *event)
{
    unsigned long persona = args->args[0];
    printf("%lx", persona);
}

void do_print_id(struct syscall_args *args, struct proc_event *event)
{
    /* uid_t type == gid_t type */
    uid_t id = (uid_t) args->args[0];
    printf("%lu", id);
}

void do_mremap(struct syscall_args *args, struct proc_event *event)
{
    void *old_addr = (void *) args->args[0];
    size_t old_size = args->args[1];
    size_t new_size = args->args[2];
    int flags = (int) args->args[3];
    void *new_addr = (void *) args->args[4];

    bool new_addr_valid = flags & MREMAP_FIXED;

    printf("%p, %lu, %lu, ", old_addr, old_size, new_size);
    bool do_or = false;

    if (flags & MREMAP_MAYMOVE)
    {
        printf("MREMAP_MAYMOVE");
        do_or = true;
    }

    if (flags & MREMAP_FIXED)
    {
        printf(do_or ? "|MREMAP_FIXED" : "MREMAP_FIXED");
    }

    if (new_addr_valid)
        printf(", %p", new_addr);
}

void do_insmod(struct syscall_args *args, struct proc_event *event)
{
    const char *path = (const char *) args->args[0];
    const char *name = (const char *) args->args[1];

    printf("%p, %p", path, name);
}

void do_uname(struct syscall_args *args, struct proc_event *event)
{
    struct utsname *uts = (struct utsname *) args->args[0];
    printf("%p", uts);
}

void do_sethostname(struct syscall_args *args, struct proc_event *event)
{
    const char *name = (const char *) args->args[0];
    size_t len = args->args[1];

    printf("%p, %lu", name, len);
}

const char *clock_ids[] = {
    [CLOCK_REALTIME] = "CLOCK_REALTIME", [CLOCK_MONOTONIC] = "CLOCK_MONOTONIC"};

const char *stringify_clk(clockid_t id)
{
    return clock_ids[id];
}

void do_clock_gettime(struct syscall_args *args, struct proc_event *event)
{
    clockid_t clk = (clockid_t) args->args[0];
    struct timespec *tp = (struct timespec *) args->args[1];
    const char *c;

    if (clk > sizeof(clock_ids) / sizeof(clock_ids[0]))
        c = "Unknown clock";
    else
        c = stringify_clk(clk);
    printf("%s, %p", c, tp);
}

void do_nanosleep(struct syscall_args *args, struct proc_event *event)
{
    const struct timespec *req = (const struct timespec *) args->args[0];
    struct timespec *rem = (struct timespec *) args->args[1];

    printf("%p, %p", req, rem);
}

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

void do_arch_prctl(struct syscall_args *args, struct proc_event *event)
{
    int code = (int) args->args[0];
    void *addr = (void *) args->args[1];
    const char *s = "Unknown";
    if (code == ARCH_SET_GS)
        s = "ARCH_SET_GS";
    else if (code == ARCH_SET_FS)
        s = "ARCH_SET_FS";
    else if (code == ARCH_GET_FS)
        s = "ARCH_GET_FS";
    else if (code == ARCH_GET_GS)
        s = "ARCH_GET_GS";

    printf("%s, %p", s, addr);
}

void do_set_tid_address(struct syscall_args *args, struct proc_event *event)
{
    void *addr = (void *) args->args[0];
    printf("%p", addr);
}

#define SYSLOG_ACTION_READ        2
#define SYSLOG_ACTION_READ_CLEAR  4
#define SYSLOG_ACTION_CLEAR       5
#define SYSLOG_ACTION_SIZE_BUFFER 10

void do_syslog(struct syscall_args *args, struct proc_event *event)
{
    int type = (int) args->args[0];
    char *buf = (char *) args->args[1];
    int len = (int) args->args[2];

    const char *type_str = "Unknown";
    if (type == SYSLOG_ACTION_READ)
        type_str = "SYSLOG_ACTION_READ";
    else if (type == SYSLOG_ACTION_READ_CLEAR)
        type_str = "SYSLOG_ACTION_READ_CLEAR";
    else if (type == SYSLOG_ACTION_CLEAR)
        type_str = "SYSLOG_ACTION_CLEAR";
    else if (type == SYSLOG_ACTION_SIZE_BUFFER)
        type_str = "SYSLOG_ACTION_SIZE_BUFFER";

    printf("%s, %p, %i", type_str, buf, len);
}

void do_fcntl(struct syscall_args *args, struct proc_event *event)
{
    int fd = (int) args->args[0];
    int cmd = (int) args->args[1];
    unsigned long arg = (unsigned long) args->args[2];

    printf("%i, ", fd);

    switch (cmd)
    {
    case F_DUPFD:
        printf("F_DUPFD, %lu", arg);
        break;
    case F_DUPFD_CLOEXEC:
        printf("F_DUPFD_CLOEXEC, %lu", arg);
        break;
    case F_GETFD:
        printf("F_GETFD");
        break;
    case F_SETFD:
        printf("F_SETFD, %lu", arg);
        break;
    }
}

void do_stat(struct syscall_args *args, struct proc_event *event)
{
    const char *pathname = (const char *) args->args[0];
    struct stat *buf = (struct stat *) args->args[1];

    printf("%p, %p", pathname, buf);
}

void do_sigaction(struct syscall_args *args, struct proc_event *event)
{
    int signum = (int) args->args[0];
    struct sigaction *act = (struct sigaction *) args->args[1];
    struct sigaction *old_act = (struct sigaction *) args->args[2];
    char *sname = get_signame(signum);

    if (sname)
        printf("%s, %p, %p", sname, act, old_act);
    else
        printf("%i, %p, %p", signum, act, old_act);
}

void do_pipe(struct syscall_args *args, struct proc_event *event)
{
    printf("%p", (int **) args->args[0]);
}

void do_memstat(struct syscall_args *args, struct proc_event *event)
{
    printf("%p", (void *) args->args[0]);
}

void do_chdir(struct syscall_args *args, struct proc_event *event)
{
    printf("%p", (void *) args->args[0]);
}

void do_fchdir(struct syscall_args *args, struct proc_event *event)
{
    printf("%i", (int) args->args[0]);
}

void do_getcwd(struct syscall_args *args, struct proc_event *event)
{
    printf("%p, %lu", (char *) args->args[0], args->args[1]);
}

void do_openat(struct syscall_args *args, struct proc_event *event)
{
    int dirfd = (int) args->args[0];
    const char *path = (const char *) args->args[1];
    int flags = (int) args->args[2];
    mode_t mode = (mode_t) args->args[3];

    /* TODO: Decode flags here and in fd-related syscalls */
    printf("%i, %p, %i, %u", dirfd, path, flags, mode);
}

void do_fstatat(struct syscall_args *args, struct proc_event *event)
{
    int dirfd = (int) args->args[0];
    const char *path = (const char *) args->args[1];
    struct stat *buf = (struct stat *) args->args[2];
    int flags = (int) args->args[3];

    printf("%i, %p, %p, %i", dirfd, path, buf, flags);
}

void do_fmount(struct syscall_args *args, struct proc_event *event)
{
    int fd = (int) args->args[0];
    const char *path = (const char *) args->args[1];
    printf("%i, %p", fd, path);
}

void do_clone(struct syscall_args *args, struct proc_event *event)
{
    void *fn = (void *) args->args[0];
    void *child_stack = (void *) args->args[1];
    int flags = (int) args->args[2];
    void *arg = (void *) args->args[3];
    pid_t *ptid = (pid_t *) args->args[4];
    void *tls = (void *) args->args[5];

    const char *flags_str = NULL;
    if (flags == CLONE_FORK)
        flags_str = "CLONE_FORK";
    else if (flags == CLONE_SPAWNTHREAD)
        flags_str = "CLONE_SPAWNTHREAD";

    if (flags_str)
        printf("%p, %p, %s, %p, %p, %p", fn, child_stack, flags_str, arg, ptid, tls);
    else
        printf("%p, %p, %x, %p, %p, %p", fn, child_stack, flags, arg, ptid, tls);
}

void do_exit_thread(struct syscall_args *args, struct proc_event *event)
{
    int val = (int) args->args[0];
    printf("%i", val);
}

void do_sigprocmask(struct syscall_args *args, struct proc_event *event)
{
    int how = (int) args->args[0];
    sigset_t *set = (sigset_t *) args->args[1];
    sigset_t *oldset = (sigset_t *) args->args[2];
    const char *how_str = NULL;

    if (how == SIG_BLOCK)
        how_str = "SIG_BLOCK";
    else if (how == SIG_UNBLOCK)
        how_str = "SIG_UNBLOCK";
    else if (how == SIG_SETMASK)
        how_str = "SIG_SETMASK";

    if (how_str)
        printf("%s, %p, %p", how_str, set, oldset);
    else
        printf("%lx, %p, %p", how, set, oldset);
}

void do_sigsuspend(struct syscall_args *args, struct proc_event *event)
{
    sigset_t *set = (sigset_t *) args->args[0];
    printf("%p", set);
}

void do_futex(struct syscall_args *args, struct proc_event *event)
{
    /* TODO: Improve this */
    void *uaddr = (void *) args->args[0];
    int futex_op = (int) args->args[1];
    int val = (int) args->args[2];
    struct timespec *arg = (struct timespec *) args->args[3];
    int *uaddr2 = (int *) args->args[4];
    int val3 = (int) args->args[5];

    printf("%p, %i, %i, %p, %p, %i", uaddr, futex_op, val, arg, uaddr2, val3);
}

void do_getrandom(struct syscall_args *args, struct proc_event *event)
{
    printf("%p, %lu, %x", (void *) args->args[0], args->args[1], (int) args->args[2]);
}

void do_socket(struct syscall_args *args, struct proc_event *event)
{
    int domain = (int) args->args[0];
    int type = (int) args->args[1];
    int protocol = (int) args->args[2];
    printf("%i, %i, %i", domain, type, protocol);
}

void do_sendto(struct syscall_args *args, struct proc_event *event)
{
    int sockfd = (int) args->args[0];
    void *buf = (void *) args->args[1];
    size_t len = (size_t) args->args[2];
    int flags = (int) args->args[3];
    struct sockaddr *addr = (struct sockaddr *) args->args[4];
    socklen_t addrlen = (socklen_t) args->args[5];

    printf("%i, %p, %lu, %x, %p, %u", sockfd, buf, len, flags, addr, addrlen);
}

void do_bind(struct syscall_args *args, struct proc_event *event)
{
    int sockfd = (int) args->args[0];
    struct sockaddr *addr = (struct sockaddr *) args->args[1];
    socklen_t addrlen = (socklen_t) args->args[2];
    printf("%i, %p, %u", sockfd, addr, addrlen);
}

void do_connect(struct syscall_args *args, struct proc_event *event)
{
    int sockfd = (int) args->args[0];
    struct sockaddr *addr = (struct sockaddr *) args->args[1];
    socklen_t addrlen = (socklen_t) args->args[2];
    printf("%i, %p, %u", sockfd, addr, addrlen);
}

void do_recvfrom(struct syscall_args *args, struct proc_event *event)
{
    int sockfd = (int) args->args[0];
    void *buf = (void *) args->args[1];
    size_t len = (size_t) args->args[2];
    int flags = (int) args->args[3];
    struct sockaddr *addr = (struct sockaddr *) args->args[4];
    socklen_t *addrlen = (socklen_t) args->args[5];

    printf("%i, %p, %lu, %x, %p, %p", sockfd, buf, len, flags, addr, addrlen);
}

void do_times(struct syscall_args *args, struct proc_event *event)
{
    printf("%p", (void *) args->args[0]);
}

void do_getrusage(struct syscall_args *args, struct proc_event *event)
{
    int who = (int) args->args[0];
    struct rusage *usage = (struct rusage *) args->args[1];

    printf("%i, %p", who, usage);
}

void do_ptrace(struct syscall_args *args, struct proc_event *event)
{
    printf("todo_implement");
}

void do_proc_event_attach(struct syscall_args *args, struct proc_event *event)
{
    pid_t pid = (pid_t) args->args[0];
    unsigned long flags = args->args[1];
    printf("%i, %lx", pid, flags);
}

void do_access(struct syscall_args *args, struct proc_event *event)
{
    printf("%p, %x", (const char *) args->args[0], (mode_t) args->args[1]);
}

struct system_call system_calls[MAX_SYS] = {
    {"write", do_write, do_long_exit},
    {"read", do_read, do_long_exit},
    {"open", do_open, do_integer_exit},
    {"close", do_close, do_integer_exit},
    {"dup", do_dup, do_integer_exit},
    {"dup2", do_dup2, do_integer_exit},
    {"getpid", do_noargs, do_integer_exit},
    {"lseek", do_lseek, do_long_exit},
    {"exit", do_exit, do_noexit},
    {"unknown", do_noargs, do_integer_exit},
    {"fork", do_noargs, do_integer_exit},
    {"mmap", do_mmap, do_mmap_exit},
    {"munmap", do_munmap, do_integer_exit},
    {"mprotect", do_mprotect, do_integer_exit},
    {"mount", do_mount, do_integer_exit},
    {"execve", do_execve, do_integer_exit},
    {"brk", do_brk, do_pointer_exit},
    {"kill", do_kill, do_integer_exit},
    {"getppid", do_noargs, do_integer_exit},
    {"wait4", do_wait4, do_integer_exit},
    {"time", do_time, do_long_exit},
    {"gettimeofday", do_gettimeofday, do_integer_exit},
    {"reboot", do_noargs, do_void_exit},
    {"unknown", do_noargs, do_integer_exit}, // TODO
    {"readv", do_print_iov, do_long_exit},
    {"writev", do_print_iov, do_long_exit},
    {"preadv", do_print_piov, do_long_exit},
    {"pwritev", do_print_piov, do_long_exit},
    {"getdents", do_getdents, do_integer_exit},
    {"ioctl", do_ioctl, do_integer_exit},
    {"truncate", do_truncate, do_integer_exit},
    {"ftruncate", do_ftruncate, do_integer_exit},
    {"personality", do_personality, do_integer_exit},
    {"setuid", do_print_id, do_integer_exit},
    {"setgid", do_print_id, do_integer_exit},
    {"unknown", do_noargs, do_integer_exit}, // TODO
    {"mremap", do_mremap, do_mmap_exit},
    {"sigreturn", do_noargs, do_noexit},
    {"insmod", do_insmod, do_integer_exit},
    {"uname", do_uname, do_integer_exit},
    {"gethostname", do_sethostname,
     do_integer_exit}, /* same args and it's good enough while we can't read args */
    {"sethostname", do_sethostname, do_integer_exit},
    {"clock_gettime", do_clock_gettime, do_integer_exit},
    {"nanosleep", do_nanosleep, do_integer_exit},
    {"arch_prctl", do_arch_prctl, do_integer_exit},
    {"set_tid_address", do_set_tid_address, do_integer_exit},
    {"syslog", do_syslog, do_integer_exit},
    {"fcntl", do_fcntl, do_integer_exit},
    {"unknown", do_noargs, do_integer_exit},
    {"stat", do_stat, do_integer_exit},
    {"unknown", do_noargs, do_integer_exit},
    {"unknown", do_noargs, do_integer_exit},
    {"sigaction", do_sigaction, do_integer_exit},
    {"pipe", do_pipe, do_integer_exit},
    {"memstat", do_memstat, do_integer_exit},
    {"chdir", do_chdir, do_integer_exit},
    {"fchdir", do_fchdir, do_integer_exit},
    {"getcwd", do_getcwd, do_integer_exit},
    {"getuid", do_noargs, do_integer_exit},
    {"getgid", do_noargs, do_integer_exit},
    {"openat", do_openat, do_integer_exit},
    {"fstatat", do_fstatat, do_integer_exit},
    {"fmount", do_fmount, do_integer_exit},
    {"clone", do_clone, do_integer_exit},
    {"exit_thread", do_exit_thread, do_noexit},
    {"sigprocmask", do_sigprocmask, do_integer_exit},
    {"sigsuspend", do_sigsuspend, do_integer_exit},
    {"pause", do_noargs, do_integer_exit},
    {"futex", do_futex, do_integer_exit},
    {"getrandom", do_getrandom, do_integer_exit},
    {"socket", do_socket, do_integer_exit},
    {"sendto", do_sendto, do_long_exit},
    {"bind", do_bind, do_integer_exit},
    {"connect", do_connect, do_integer_exit},
    {"recvfrom", do_recvfrom, do_long_exit},
    {"times", do_times, do_long_exit},
    {"getrusage", do_getrusage, do_integer_exit},
    {"unknown", do_noargs, do_integer_exit},
    {"unknown", do_noargs, do_integer_exit},
    {"proc_event_attach", do_proc_event_attach, do_integer_exit},
    {"access", do_access, do_integer_exit}};

void print_syscall(struct proc_event *event)
{
    size_t nr = event->e_un.syscall.rax;
    if ((nr < MAX_SYS && !system_calls[nr].callback) || nr >= MAX_SYS)
    {
        printf("unknown_sys(%lu) ", nr);
    }
    else
    {
        struct syscall_args args;
        args.args[0] = event->e_un.syscall.rdi;
        args.args[1] = event->e_un.syscall.rsi;
        args.args[2] = event->e_un.syscall.rdx;
        args.args[3] = event->e_un.syscall.r10;
        args.args[4] = event->e_un.syscall.r8;
        args.args[5] = event->e_un.syscall.r9;
        printf("%s(", system_calls[nr].name);
        system_calls[nr].callback(&args, event);
        printf(") = ");
    }
}

void print_syscall_exit(struct proc_event *event)
{
    size_t nr = event->e_un.syscall_exit.syscall_nr;
    if ((nr < MAX_SYS && !system_calls[nr].exit) || nr >= MAX_SYS)
    {
        do_integer_exit((size_t) event->e_un.syscall_exit.retval, event);
    }
    else
        system_calls[nr].exit((size_t) event->e_un.syscall_exit.retval, event);

    printf("\n");
}

void strace_print_event(struct proc_event *event)
{
    if (event->type == PROC_EVENT_SYSCALL_ENTER)
    {
        print_syscall(event);
    }
    else if (event->type == PROC_EVENT_SYSCALL_EXIT)
    {
        print_syscall_exit(event);
    }
}
