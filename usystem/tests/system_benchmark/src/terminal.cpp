/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <unistd.h>

#include <benchmark/benchmark.h>

static void terminal_scroll_bench(benchmark::State &state)
{
    for (int i = 0; i < 100; i++)
        write(STDOUT_FILENO, "\033[B", strlen("\033[B"));

    for (auto _ : state)
    {
        write(STDOUT_FILENO, "\n", 1);
    }
}

BENCHMARK(terminal_scroll_bench);
