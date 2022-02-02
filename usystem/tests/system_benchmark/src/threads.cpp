/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <iostream>
#include <stdexcept>
#include <thread>

#include <benchmark/benchmark.h>

static void thread_spawning_bench(benchmark::State& state)
{
    for (auto _ : state)
    {
        auto nr_threads = state.range(0);
        std::vector<std::thread> v;

        for (unsigned int i = 0; i < nr_threads; i++)
            v.emplace_back([&]() {});

        for (auto& t : v)
            t.join();
    }
}

BENCHMARK(thread_spawning_bench)->RangeMultiplier(2)->Range(8, 8 << 10);
;
