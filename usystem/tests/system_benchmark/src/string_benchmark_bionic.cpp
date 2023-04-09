/*
 * Copyright (C) 2012 The Android Open Source Project
 * Copyright (c) 2022 - 2023 Pedro Falcato
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>
#include <string.h>

#include <benchmark/benchmark.h>

#define KB 1024
#define MB 1024 * KB
#define AT_COMMON_SIZES \
    Arg(4)              \
        ->Arg(8)        \
        ->Arg(16)       \
        ->Arg(32)       \
        ->Arg(64)       \
        ->Arg(128)      \
        ->Arg(150)      \
        ->Arg(192)      \
        ->Arg(256)      \
        ->Arg(384)      \
        ->Arg(512)      \
        ->Arg(1 * KB)   \
        ->Arg(4 * KB)   \
        ->Arg(8 * KB)   \
        ->Arg(16 * KB)  \
        ->Arg(32 * KB)  \
        ->Arg(64 * KB)

// TODO: test unaligned operation too? (currently everything will be 8-byte aligned by malloc.)
void BM_string_memcmp(benchmark::State& state)
{
    const auto nbytes = state.range();
    char* src = new char[nbytes];
    char* dst = new char[nbytes];
    memset(src, 'x', nbytes);
    memset(dst, 'x', nbytes);

    for (auto _ : state)
    {
        auto val = memcmp(dst, src, nbytes);
        benchmark::DoNotOptimize(val);
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(state.iterations() * nbytes);
    delete[] src;
    delete[] dst;
}

BENCHMARK(BM_string_memcmp)->AT_COMMON_SIZES;

void BM_string_memcpy(benchmark::State& state)
{
    const auto nbytes = state.range();
    char* src = new char[nbytes];
    char* dst = new char[nbytes];
    memset(src, 'x', nbytes);
    memset(dst, 'x', nbytes);

    for (auto _ : state)
    {
        auto val = memcpy(dst, src, nbytes);
        benchmark::DoNotOptimize(val);
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(state.iterations() * nbytes);
    delete[] src;
    delete[] dst;
}

BENCHMARK(BM_string_memcpy)->AT_COMMON_SIZES;

void BM_string_memmove(benchmark::State& state)
{
    const auto nbytes = state.range();
    char* buf = new char[nbytes + 64];
    memset(buf, 'x', nbytes + 64);

    for (auto _ : state)
    {
        auto val = memmove(buf, buf + 1, nbytes); // Worst-case overlap.
        benchmark::DoNotOptimize(val);
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(state.iterations() * nbytes);
    delete[] buf;
}

BENCHMARK(BM_string_memmove)->AT_COMMON_SIZES;

void BM_string_memset(benchmark::State& state)
{
    const auto nbytes = state.range();
    char* dst = new char[nbytes];

    for (auto _ : state)
    {
        auto ret = memset(dst, 0, nbytes);
        benchmark::DoNotOptimize(ret);
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(state.iterations() * nbytes);
    delete[] dst;
}
BENCHMARK(BM_string_memset)->AT_COMMON_SIZES;

void BM_string_strlen(benchmark::State& state)
{
    const auto nbytes = state.range();
    char* s = new char[nbytes];
    memset(s, 'x', nbytes);
    s[nbytes - 1] = 0;

    for (auto _ : state)
    {
        auto len = strlen(s);
        benchmark::DoNotOptimize(len);
    }

    state.SetBytesProcessed(state.iterations() * nbytes);
    delete[] s;
}
BENCHMARK(BM_string_strlen)->AT_COMMON_SIZES;
