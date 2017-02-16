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
#ifndef _SIGNAL_H
#define _SIGNAL_H
#include <sys/cdefs.h>
#include <sys/types.h>

#ifdef __cplusplus
__START_C_HEADER
#endif

typedef int sig_atomic_t;
typedef int(*sighandler_t)(int);
int kill(pid_t, int);
int raise(int);
sighandler_t signal(int signum, sighandler_t handler);

/* Signal numbers, as required by POSIX and the ISO C standard */
#define SIGABRT 1
#define SIGFPE 2
#define SIGILL 3
#define SIGINT 4
#define SIGSEGV 5
#define SIGTERM 6
#define SIGKILL 7
#define SIGQUIT 8
#define SIGSTOP 9
#define SIGALRM 10
#define SIGBUS 11
#define SIGCHLD 12
#define SIGPIPE 13
#define SIGTERM 14
#define SIGTSTP 15
#define SIGTTIN 16
#define SIGTTOU 17
#define SIGUSR1 18
#define SIGUSR2 19
#define SIGPOLL 20
#define SIGPROF 21
#define SIGSYS 22
#define SIGTRAP 23
#define SIGURG 24
#define SIGVTALRM 25
#define SIGXCPU 26
#define SIGXFSZ 27

/* Defines for signal() */
#define SIG_DFL 0
#define SIG_ERR -1
#define SIG_HOLD 1
#define SIG_IGN 2

typedef int sigset_t;
// HACK!
#define SIG_SETMASK 1
#ifdef __cplusplus
__END_C_HEADER
#endif
#endif
