/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <sys/mman.h>

#include <benchmark/benchmark.h>

static void read_fault_bench(benchmark::State& state)
{
    for (auto _ : state)
    {
        void* ptr = mmap(nullptr, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
        assert(ptr != MAP_FAILED);
        volatile int* p = (volatile int*) ptr;
        benchmark::DoNotOptimize(*p);
        benchmark::ClobberMemory();
        munmap(ptr, 4096);
    }
}

BENCHMARK(read_fault_bench);

static void write_fault_bench(benchmark::State& state)
{
    for (auto _ : state)
    {
        void* ptr = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
        assert(ptr != MAP_FAILED);
        volatile int* p = (volatile int*) ptr;
        *p = 10;
        benchmark::ClobberMemory();
        munmap(ptr, 4096);
    }
}

BENCHMARK(write_fault_bench);
