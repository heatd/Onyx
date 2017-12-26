/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

#include <proc_event.h>

#include <sys/mman.h>

#include "errnos.h"

#define MAX_ARGS 8

/* HACK! */
#define MAX_SYS		500

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
	if(err >= NUM_ERRNOS)
	{
		err_name = __errno_table[0];
	}
	else	err_name = __errno_table[err];

	printf("%s", err_name);
}

void do_write(struct syscall_args *args, struct proc_event *event)
{
	printf("%u, %p, %lu", args->args[0], args->args[1], args->args[2]);
}

void do_long_exit(size_t return_value, struct proc_event *event)
{
	ssize_t ret = (ssize_t) return_value;

	if(ret < 0)
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

	if(ret < 0)
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
	printf("%p", (void*) return_value);
}

void do_mmap_exit(size_t return_value, struct proc_event *event)
{
	void *ptr = (void*) return_value;
	if(ptr == MAP_FAILED)
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

	switch(whence)
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

	if(whence_str)	printf("%d, %ld, %s", fd, offset, whence_str);
	else		printf("%d, %ld, %d", fd, offset, whence);
}

void do_exit(struct syscall_args *args, struct proc_event *event)
{
	printf("%d", args->args[0]);
}

void do_mmap(struct syscall_args *args, struct proc_event *event)
{
	void *addr = (void*) args->args[0];
	size_t len = args->args[1];
	int prot = (int) args->args[2];
	int flags = (int) args->args[3];
	int fildes = (int) args->args[4];
	off_t off = (off_t) args->args[5];

	printf("%p, %lu, ", addr, len);

	if(prot == PROT_NONE)
	{
		printf("PROT_NONE, ");
	}
	else
	{
		bool do_or = false;
		if(prot & PROT_READ)
		{
			printf("PROT_READ");
			do_or = true;
		}

		if(prot & PROT_WRITE)
		{
			printf(do_or ? "|PROT_WRITE" : "PROT_WRITE");
			do_or = true;
		}

		if(prot & PROT_EXEC)
		{
			printf(do_or ? "|PROT_EXEC" : "PROT_EXEC");
			do_or = true;
		}
		printf(", ");
	}

	bool do_or = false;
	if(flags & MAP_PRIVATE)
	{
		printf("MAP_PRIVATE");
		do_or = true;
	}

	if(flags & MAP_SHARED)
	{
		printf("MAP_SHARED");
		do_or = true;
	}

	if(flags & MAP_ANONYMOUS)
	{
		printf("MAP_ANONYMOUS");
		do_or = true;
	}

	/* TODO: Add flags as needed */
	printf(", %d, %ld", fildes, off);
}
struct system_call system_calls[MAX_SYS] = 
{
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
	{"mmap", do_mmap, do_pointer_exit}
};

void print_syscall(struct proc_event *event)
{
	size_t nr = event->e_un.syscall.rax;
	if((nr < MAX_SYS && !system_calls[nr].callback) || nr >= MAX_SYS)
	{
		printf("unknown_sys(%lu) ", nr);
	}
	else
	{
		struct syscall_args args;
		args.args[0] = event->e_un.syscall.rdi;
		args.args[1] = event->e_un.syscall.rsi;
		args.args[2] = event->e_un.syscall.rdx;
		args.args[3] = event->e_un.syscall.rcx;
		args.args[4] = event->e_un.syscall.r8;
		args.args[5] = event->e_un.syscall.r9;
		printf("%s(", system_calls[nr].name);
		system_calls[nr].callback(&args, event);
		printf(") ");
	}
}

void strace_print_event(struct proc_event *event)
{
	if(event->type == PROC_EVENT_SYSCALL_ENTER)
	{
		printf("syscall\n");
		print_syscall(event);
	}
	else if(event->type == PROC_EVENT_SYSCALL_EXIT)
	{
		//print_syscall_exit(event);
	}
}
