/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <sys/wait.h>
#include <unistd.h>

#include <exception>
#include <stdexcept>

#include <benchmark/benchmark.h>

static void fork_bench(benchmark::State& state)
{
    for (auto _ : state)
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            throw std::runtime_error("Failed to fork");
        }
        else if (pid == 0)
        {
            _exit(0);
        }
    }

    while (waitpid(-1, nullptr, 0) != -1)
        ;
}

BENCHMARK(fork_bench)->ThreadRange(1, 16);

static void vfork_bench(benchmark::State& state)
{
    for (auto _ : state)
    {
        pid_t pid = vfork();
        if (pid < 0)
        {
            throw std::runtime_error("Failed to fork");
        }
        else if (pid == 0)
        {
            _exit(0);
        }
    }

    while (waitpid(-1, nullptr, 0) != -1)
        ;
}

BENCHMARK(vfork_bench)->ThreadRange(1, 16);
