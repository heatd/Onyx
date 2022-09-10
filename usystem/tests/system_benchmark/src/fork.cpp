/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <unistd.h>

#include <exception>
#include <stdexcept>

#include <benchmark/benchmark.h>

static void fork_bench(benchmark::State& state)
{
    while (state.KeepRunning())
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            throw std::runtime_error("Failed to open fd");
        }
        else if (pid == 0)
        {
            _exit(0);
        }
    }
}

BENCHMARK(fork_bench);
