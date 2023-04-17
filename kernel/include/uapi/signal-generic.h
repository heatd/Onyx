/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_SIGNAL_GENERIC_H
#define _UAPI_SIGNAL_GENERIC_H

#include <onyx/types.h>

#include <uapi/posix-types.h>

#define MINSIGSTKSZ 2048
#define SIGSTKSZ    8192

#define SIG_BLOCK   0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

#define SI_ASYNCNL (-60)
#define SI_TKILL   (-6)
#define SI_SIGIO   (-5)
#define SI_ASYNCIO (-4)
#define SI_MESGQ   (-3)
#define SI_TIMER   (-2)
#define SI_QUEUE   (-1)
#define SI_USER    0
#define SI_KERNEL  128

struct sigaltstack
{
    void *ss_sp;
    int ss_flags;
    __usize ss_size;
};

#ifdef __is_onyx_kernel
typedef struct sigaltstack stack_t;
#endif

#define _SIGSET_SIZE (64 / 8 / sizeof(long))

typedef struct __sigset_t
{
    unsigned long __bits[_SIGSET_SIZE];
} sigset_t;

typedef struct __ucontext
{
    unsigned long uc_flags;
    struct __ucontext *uc_link;
    struct sigaltstack uc_stack;
    mcontext_t uc_mcontext;
    sigset_t uc_sigmask;
    unsigned long __fpregs_mem[64];
} ucontext_t;

#define SA_NOCLDSTOP 1
#define SA_NOCLDWAIT 2
#define SA_SIGINFO   4
#define SA_ONSTACK   0x08000000
#define SA_RESTART   0x10000000
#define SA_NODEFER   0x40000000
#define SA_RESETHAND 0x80000000
#define SA_RESTORER  0x04000000

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#define SIGTRAP   5
#define SIGABRT   6
#define SIGIOT    SIGABRT
#define SIGBUS    7
#define SIGFPE    8
#define SIGKILL   9
#define SIGUSR1   10
#define SIGSEGV   11
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGPROF   27
#define SIGWINCH  28
#define SIGIO     29
#define SIGPOLL   29
#define SIGPWR    30
#define SIGSYS    31
#define SIGUNUSED SIGSYS

#define _NSIG 65

#define _NSIG_PER_WORD (_NSIG - 1)

#define _NSIG_WORDS (_NSIG / _NSIG_PER_WORD)

#define FPE_INTDIV 1
#define FPE_INTOVF 2
#define FPE_FLTDIV 3
#define FPE_FLTOVF 4
#define FPE_FLTUND 5
#define FPE_FLTRES 6
#define FPE_FLTINV 7
#define FPE_FLTSUB 8

#define ILL_ILLOPC 1
#define ILL_ILLOPN 2
#define ILL_ILLADR 3
#define ILL_ILLTRP 4
#define ILL_PRVOPC 5
#define ILL_PRVREG 6
#define ILL_COPROC 7
#define ILL_BADSTK 8

#define SEGV_MAPERR 1
#define SEGV_ACCERR 2
#define SEGV_BNDERR 3
#define SEGV_PKUERR 4

#define BUS_ADRALN    1
#define BUS_ADRERR    2
#define BUS_OBJERR    3
#define BUS_MCEERR_AR 4
#define BUS_MCEERR_AO 5

#define CLD_EXITED    1
#define CLD_KILLED    2
#define CLD_DUMPED    3
#define CLD_TRAPPED   4
#define CLD_STOPPED   5
#define CLD_CONTINUED 6

union sigval {
    int sival_int;
    void *sival_ptr;
};

typedef struct siginfo
{
#ifdef __SI_SWAP_ERRNO_CODE
    int si_signo, si_code, si_errno;
#else
    int si_signo, si_errno, si_code;
#endif
    union {
        char __pad[128 - 2 * sizeof(int) - sizeof(long)];
        struct
        {
            union {
                struct
                {
                    __pid_t si_pid;
                    __uid_t si_uid;
                } __piduid;
                struct
                {
                    int si_timerid;
                    int si_overrun;
                } __timer;
            } __first;
            union {
                union sigval si_value;
                struct
                {
                    int si_status;
                    __clock_t si_utime, si_stime;
                } __sigchld;
            } __second;
        } __si_common;
        struct
        {
            void *si_addr;
            short si_addr_lsb;
            union {
                struct
                {
                    void *si_lower;
                    void *si_upper;
                } __addr_bnd;
                unsigned si_pkey;
            } __first;
        } __sigfault;
        struct
        {
            long si_band;
            int si_fd;
        } __sigpoll;
        struct
        {
            void *si_call_addr;
            int si_syscall;
            unsigned si_arch;
        } __sigsys;
    } __si_fields;
} siginfo_t;
#define si_pid       __si_fields.__si_common.__first.__piduid.si_pid
#define si_uid       __si_fields.__si_common.__first.__piduid.si_uid
#define si_status    __si_fields.__si_common.__second.__sigchld.si_status
#define si_utime     __si_fields.__si_common.__second.__sigchld.si_utime
#define si_stime     __si_fields.__si_common.__second.__sigchld.si_stime
#define si_value     __si_fields.__si_common.__second.si_value
#define si_addr      __si_fields.__sigfault.si_addr
#define si_addr_lsb  __si_fields.__sigfault.si_addr_lsb
#define si_lower     __si_fields.__sigfault.__first.__addr_bnd.si_lower
#define si_upper     __si_fields.__sigfault.__first.__addr_bnd.si_upper
#define si_pkey      __si_fields.__sigfault.__first.si_pkey
#define si_band      __si_fields.__sigpoll.si_band
#define si_fd        __si_fields.__sigpoll.si_fd
#define si_timerid   __si_fields.__si_common.__first.__timer.si_timerid
#define si_overrun   __si_fields.__si_common.__first.__timer.si_overrun
#define si_ptr       si_value.sival_ptr
#define si_int       si_value.sival_int
#define si_call_addr __si_fields.__sigsys.si_call_addr
#define si_syscall   __si_fields.__sigsys.si_syscall
#define si_arch      __si_fields.__sigsys.si_arch

struct k_sigaction
{
    union {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, siginfo_t *, void *);
    } __sa_handler;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    unsigned int sa_mask[2];
};

#define sa_handler   __sa_handler.sa_handler
#define sa_sigaction __sa_handler.sa_sigaction

struct sigevent
{
    union sigval sigev_value;
    int sigev_signo;
    int sigev_notify;
    void (*sigev_notify_function)(union sigval);
    void *sigev_notify_attributes;
    char __pad[56 - 3 * sizeof(long)];
};

#define SIGEV_SIGNAL    0
#define SIGEV_NONE      1
#define SIGEV_THREAD    2
#define SIGEV_THREAD_ID 4

#define TRAP_BRKPT    1
#define TRAP_TRACE    2
#define POLL_IN       1
#define POLL_OUT      2
#define POLL_MSG      3
#define POLL_ERR      4
#define POLL_PRI      5
#define POLL_HUP      6
#define SS_ONSTACK    1
#define SS_DISABLE    2
#define SS_AUTODISARM (1U << 31)
#define SS_FLAG_BITS  SS_AUTODISARM

#define SA_NOMASK  SA_NODEFER
#define SA_ONESHOT SA_RESETHAND

#define SIG_ERR ((void (*)(int)) - 1)
#define SIG_DFL ((void (*)(int)) 0)
#define SIG_IGN ((void (*)(int)) 1)

typedef void (*__sighandler_t)(int);

#ifdef __is_onyx_kernel
typedef __sighandler_t sighandler_t;
#define NSIG _NSIG

#endif

#endif
