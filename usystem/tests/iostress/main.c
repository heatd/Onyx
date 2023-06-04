/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int prepare_file(const char *filename, size_t size)
{
    int fd = open(filename, O_RDWR | O_TRUNC | O_CREAT | O_CLOEXEC, 0666);

    if (fd < 0)
    {
        err(1, "open %s", filename);
    }

    if (ftruncate(fd, size) < 0)
    {
        err(1, "ftruncate");
    }

    return fd;
}

struct stress_options
{
    // if sequential IO, else random
    bool sequential;
    // IO chunk size
    int io_chunk_size;
    // File size
    size_t file_size;
    // Time to run
    int time_secs;
    // file descriptor
    int fd;
};

static volatile sig_atomic_t test_done = 0;

static void test_alrm(int sig)
{
    (void) sig;
    test_done = 1;
}

static void stress(int fd, struct stress_options *opts)
{
    void *block = calloc(opts->io_chunk_size, 1);
    if (!block)
        err(1, "malloc");

    struct stat buf0, buf1;
    off_t off = 0;

    if (fstat(fd, &buf0) < 0)
        err(1, "fstat");

    signal(SIGALRM, test_alrm);
    alarm(opts->time_secs);

    while (!test_done)
    {
        ssize_t st;
        if (opts->sequential)
            st = write(fd, block, opts->io_chunk_size);
        else
        {
            /* Calculate the number of blocks */
            size_t nr_blocks = opts->file_size / opts->io_chunk_size;
            off = rand() % nr_blocks;
            st = pwrite(fd, block, opts->io_chunk_size, off * opts->io_chunk_size);
        }

        if (st != opts->io_chunk_size)
        {
            fprintf(stderr, "stress: partial write (supposedly, offset %ld size %d, written %zd)\n",
                    off, opts->io_chunk_size, st);
            exit(1);
        }

        if (st < 0)
            err(1, "write");
        off += opts->io_chunk_size;
    }
}

static int sequential = 0;

const static struct option options[] = {
    {"version", no_argument, NULL, 'v'},           {"help", no_argument, NULL, 'h'},
    {"threads", required_argument, NULL, 't'},     {"sequential", no_argument, &sequential, 1},
    {"file-size", required_argument, NULL, 1},     {"time", required_argument, NULL, 2},
    {"io-block-size", required_argument, NULL, 3}, {}};

static int threads = 1;
static unsigned long file_size = 0x400000;
static int timeout = 10;
static int io_block_size = 4096;

static void *stress_thread_start(void *arg)
{
    struct stress_options *opts = arg;
    stress(opts->fd, opts);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "%s: usage: %s filename\n", argv[0], argv[0]);
        return 1;
    }

    int optindex = 0;
    int opt;
    while ((opt = getopt_long_only(argc, argv, "vht:s", options, &optindex)) != -1)
    {
        switch (opt)
        {
            case 'v':
                printf("iostress version 04062023\n");
                return 0;
            case 'h':
            case '?':
                printf("'help'\n");
                return 0;
            case 't':
                errno = 0;
                threads = strtoul(optarg, NULL, 0);
                if (errno == ERANGE || threads == 0)
                {
                    printf("iostress: Threads number out of range [1, UINT_MAX]\n");
                    return 1;
                }

                break;
            case 's':
                sequential = 1;
                break;
            case 1:
                // --file-size
                errno = 0;
                file_size = strtoul(optarg, NULL, 0);
                if (errno == ERANGE || file_size == 0)
                {
                    printf("iostress: File size number out of range [1, ULONG_MAX]\n");
                    return 1;
                }

                break;
            case 2:
                errno = 0;
                timeout = strtoul(optarg, NULL, 0);
                if (errno == ERANGE || file_size == 0)
                {
                    printf("iostress: Timeout number out of range [1, ULONG_MAX]\n");
                    return 1;
                }

                break;
            case 3:
                errno = 0;
                io_block_size = strtoul(optarg, NULL, 0);
                if (errno == ERANGE || io_block_size == 0)
                {
                    printf("iostress: IO block size number out of range [1, ULONG_MAX]\n");
                    return 1;
                }

                break;
        }
    }

    if (sequential && threads != 1)
    {
        // TODO(pedro): make these compatible (dup fds)
        fprintf(stderr, "iostress: error: sequential and multiple threads is incompatible!\n");
        return 1;
    }

    if ((unsigned long) io_block_size > file_size)
    {
        fprintf(stderr, "iostress: error: io block size must not be larger than file_size\n");
        return 1;
    }

    srand(time(NULL));

    const char *filename = argv[1];

    int fd = prepare_file(filename, file_size);

    struct stress_options opts;
    opts.file_size = file_size;
    opts.sequential = sequential;
    opts.io_chunk_size = io_block_size;
    opts.time_secs = timeout;
    opts.fd = fd;

    pthread_t ids[threads - 1];

    for (int i = 1; i < threads; i++)
    {
        int st = pthread_create(&ids[i - 1], NULL, stress_thread_start, &opts);
        if (st)
        {
            errno = st;
            err(1, "pthread_create");
        }
    }

    stress(fd, &opts);

    for (int i = 0; i < threads - 1; i++)
    {
        pthread_join(ids[i], NULL);
    }
}
