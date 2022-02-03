/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <proc_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

void strace_print_event(struct proc_event *event);

int proc_event_attach(pid_t pid, unsigned long flags)
{
    return (int) syscall(SYS_proc_event_attach, pid, flags);
}

void do_trace(pid_t p);

void *do_pt_trace(void *arg)
{
    do_trace((pid_t) (unsigned long) arg);

    return (void *) 0;
}

void do_child_trace(pid_t pid)
{
    pthread_t thread;
    if (pthread_create(&thread, NULL, do_pt_trace, (void *) (unsigned long) pid) < 0)
    {
        perror("pthread_create");
        return;
    }
}

void do_trace(pid_t pid)
{
    int fd = proc_event_attach(pid, PROC_EVENT_LISTEN_SYSCALLS);
    if (fd < 0)
    {
        perror("proc_event_attach");
    }

    struct proc_event event = {0};

    while (read(fd, &event, sizeof(struct proc_event)))
    {
        /* Print the event and send an ACK */
        strace_print_event(&event);

        if (event.type == PROC_EVENT_SYSCALL_EXIT &&
            event.e_un.syscall_exit.syscall_nr == SYS_execve)
            do_child_trace(event.e_un.syscall_exit.retval);
        ioctl(fd, 0);
    }
}

void do_child(int argc, char **argv)
{
    printf("Being traced!\n");
    if (execvp(argv[0], argv) < 0)
        exit(1);
}

void print_usage(char *prog)
{
    printf("%s - system call tracer\nUsage: %s [program] [args] ...\n", prog, prog);
}

int main(int argc, char **argv, char **envp)
{
    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        perror("strace");
        return 1;
    }
    else if (pid > 0)
    {
        do_trace(pid);
    }
    else
    {
        do_child(argc - 1, argv + 1);
    }

    return 0;
}
