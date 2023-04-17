/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>

#include <uapi/memstat.h>

#include <test/libtest.h>

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
