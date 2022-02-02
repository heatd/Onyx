/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>

#include <onyx/public/memstat.h>

#include <test/libtest.h>

static void print_mem_usage()
{
    struct memstat stat;
    int st = syscall(SYS_memstat, &stat);
    if (st < 0)
    {
        perror("memstat");
        return;
    }

    printf("Page cache usage: %lu\nTotal usage: %lu\nKernel heap usage: %lu\n",
           stat.page_cache_pages, stat.allocated_pages, stat.kernel_heap_pages);
}

pid_t first_child = 0;

static void start_forking(unsigned int order)
{
    while (order--)
    {
        pid_t pid = fork();

        if (pid < 0)
        {
            perror("start_forking");
            std::exit(1);
        }
    }

    std::exit(0);
}

bool fork_test()
{
    printf("Printing starting memory usage...\n");

    pid_t pid = fork();
    if (pid == 0)
    {
        first_child = getpid();
        start_forking(12);
    }
    else if (pid > 0)
    {
        if (waitpid(pid, nullptr, 0) < 0)
        {
            perror("waitpid");
            return false;
        }
    }
    else
    {
        perror("fork");
    }

    sleep(1);

    return true;
}

DECLARE_TEST(fork_test, 5);
