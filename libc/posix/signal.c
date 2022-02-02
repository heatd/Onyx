/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#pragma GCC push_options
#pragma GCC diagnostic ignored "-Wunused-parameter"
int kill(pid_t pid, int sig)
{
    return 0;
}
int raise(int signal)
{
    return kill(getpid(), signal);
}
#pragma GCC pop_options
