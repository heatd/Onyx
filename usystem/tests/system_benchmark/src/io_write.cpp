/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>

#include <stdexcept>
#include <vector>

#include <benchmark/benchmark.h>

static void io_write_seq_bench(benchmark::State& state)
{
    int fd = open("tmpfile", O_RDWR | O_CREAT | O_EXCL);

    if (fd < 0)
    {
        throw std::runtime_error("Failed to open fd");
    }

    unlink("tmpfile");

    size_t bytes_written = 0;

    std::vector<char> page(state.range(), 0);

    if (getrandom(page.data(), page.size(), 0) < 0)
        throw std::runtime_error("Failed to get random");

    while (state.KeepRunning())
    {
        if (write(fd, page.data(), page.size()) < 0)
            throw std::runtime_error("Failed to write");
        bytes_written += page.size();
    }

    state.SetBytesProcessed(bytes_written);

    close(fd);
}

BENCHMARK(io_write_seq_bench)->RangeMultiplier(2)->Range(8, 8 << 13);
