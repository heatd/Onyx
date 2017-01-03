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
/* My Operating System is aiming for POSIX compliance, so this header is needed */
#ifndef _UNISTD_H
#define _UNISTD_H
#include <sys/types.h>

/* This is complying with POSIX-1.2008 */
#define _POSIX_VERSION 	200809L
#define _POSIX2_VERSION 200809L

#define _XOPEN_VERSION 700

/* According to POSIX-1.2008, stuff that isn't supported shall be set with the value -1 */
#define _POSIX_ADVISORY_INFO 	-1
#define _POSIX_ASYNCHRONOUS_IO 	-1
#define _POSIX_BARRIERS		-1
#define _POSIX_CHOWN_RESTRICTED	-1
#define _POSIX_CLOCK_SELECTION	-1
#define _POSIX_CPUTIME		200809L
#define _POSIX_FSYNC		-1
#define _POSIX_IPV6		-1
#define _POSIX_JOB_CONTROL	1
#define _POSIX_MAPPED_FILES	200809L
#define _POSIX_MEMLOCK		-1
#define _POSIX_MEMLOCK_RANGE	-1
#define _POSIX_MEMORY_PROTECTION 200809L
#define _POSIX_MESSAGE_PASSING	-1
#define _POSIX_MONOTONIC_CLOCK	-1
#define	_POSIX_NO_TRUNC		1
#define _POSIX_PRIORITIZED_IO	-1
#define _POSIX_PRIORITY_SCHEDULING -1
#define _POSIX_RAW_SOCKETS	-1
#define _POSIX_READER_WRITER_LOCKS 200809L
#define _POSIX_REALTIME_SIGNALS	200809L
#define _POSIX_REGEXP		200809L
#define _POSIX_SAVED_IDS	1
#define _POSIX_SEMAPHORES	200809L
#define _POSIX_SHARED_MEMORY_OBJECTS -1
#define _POSIX_SHELL		1
#define _POSIX_SPAWN		200809L
#define _POSIX_SPIN_LOCKS	200809L
#define _POSIX_SPORADIC_SERVER	-1
#define _POSIX_SYNCHRONIZED_IO	200809L
#define _POSIX_THREAD_ATTR_STACKADDR 200809L
#define _POSIX_THREAD_ATTR_STACKSIZE 200809L
#define _POSIX_THREAD_CPUTIME	200809L
#define _POSIX_THREAD_PRIO_INHERIT -1
#define _POSIX_THREAD_PRIO_PROTECT -1
#define _POSIX_THREAD_PRIORITY_SCHEDULING -1
#define _POSIX_THREAD_PROCESS_SHARED -1
#define _POSIX_THREAD_ROBUST_PRIO_INHERIT -1
#define _POSIX_THREAD_ROBUST_PRIO_PROTECT -1
#define _POSIX_THREAD_SAFE_FUNCTIONS 200809L
#define _POSIX_THREAD_SPORADIC_SERVER -1
#define _POSIX_THREADS 		200809L
#define _POSIX_TIMEOUTS		200809L
#define _POSIX_TIMERS		200809L
#define _POSIX_TRACE		-1
#define _POSIX_TRACE_EVENT_FILTER -1
#define _POSIX_TRACE_LOG	-1
#define _POSIX_TYPED_MEMORY_OBJECTS -1
#ifdef __i386__
#define _POSIX_V6_ILP32_OFF32 	1
#endif // __i386__
#define _POSIX2_C_BIND 		200809L
#define _POSIX2_C_DEV		200809L
#define _POSIX2_CHAR_TERM	-1
#define _POSIX2_FORT_DEV	-1
#define _POSIX2_FORT_RUN	-1
#define _POSIX2_LOCALEDEF	-1
#define _POSIX2_PBS		-1
#define _POSIX2_PBS_ACCOUNTING	-1
#define _POSIX2_PBS_CHECKPOINT	-1
#define _POSIX2_PBS_LOCATE	-1
#define _POSIX2_PBS_MESSAGE	-1
#define _POSIX2_PBS_TRACK	-1
#define _POSIX2_SW_DEV		200809L
#define _POSIX2_UPE		200809L
#define _XOPEN_ENH_I18N		-1
#define _XOPEN_SHM		1
#define _XOPEN_UUCP		-1

/* lseek(2) */
#define SEEK_SET 1
#define SEEK_CUR 2
#define SEEK_END 3

/* Standard file descriptors required by POSIX */
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

pid_t fork();
int execv(const char* path, char* const argv[]);
int execvp(const char* file, char* const argv[]);
int execve(const char* filename, char* const argv[],char* const envp[]);
int open(const char*, int flags);
int close(int fd);
int read(int fd, void *buf, unsigned int count);
int write(int fd, void *buf, unsigned int count);
unsigned long lseek(int fd, unsigned long offset, int whence);
int brk(void* addr);
void* sbrk(unsigned long long inc);
void _exit(int exit_code);
pid_t getpid();
pid_t getppid();
int setuid(uid_t uid);
int setgid(gid_t gid);

#endif
