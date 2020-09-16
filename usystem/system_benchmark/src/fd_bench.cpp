/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>

#include <benchmark/benchmark.h>

static void fd_open_close_bench(benchmark::State& state)
{
	while(state.KeepRunning())
	{
		int fd = open("/dev/null", O_RDONLY);

		if(fd < 0)
		{
			throw std::runtime_error("Failed to open fd");
		}

		close(fd);
	}
}

BENCHMARK(fd_open_close_bench)->Threads(4);

BENCHMARK_MAIN();
