/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int direct_io = 0;
static int do_fsync;
static int do_fsync_dir;

static int prepare_file(const char *filename, size_t size)
{
    int oflags = O_RDWR | O_TRUNC | O_CREAT | O_CLOEXEC;
    bool notrunc = false;
    struct stat buf;

    if (stat(filename, &buf) < 0 && errno != ENOENT)
        err(1, "prepare_file: stat");

    if (S_ISBLK(buf.st_mode))
    {
        oflags &= ~(O_CREAT | O_TRUNC);
        notrunc = true;
    }

    if (direct_io)
        oflags |= O_DIRECT;

    int fd = open(filename, oflags, 0666);

    if (fd < 0)
    {
        err(1, "open %s", filename);
    }

    if (do_fsync_dir)
    {
        /* Sync the directory - this lets us more easily isolate IO on the actual file, for testing
         * purposes.
         */
        char path[PATH_MAX];
        strcpy(path, filename);
        int fd2 = open(dirname(path), O_RDONLY | O_CLOEXEC);
        if (fd2 < 0)
            err(1, "open %s", dirname(path));
        if (fsync(fd2) < 0)
            err(1, "fsync");
        close(fd2);
    }

    if (!notrunc)
    {
        if (ftruncate(fd, size) < 0)
        {
            err(1, "ftruncate");
        }
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
    void *block = aligned_alloc(opts->io_chunk_size, opts->io_chunk_size);
    if (!block)
        err(1, "malloc");
    memset(block, 0, opts->io_chunk_size);

    struct stat buf0;
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
            off = (rand() % nr_blocks) * opts->io_chunk_size;
            st = pwrite(fd, block, opts->io_chunk_size, off);
        }

        if (st < 0)
            err(1, "write");

        if (st != opts->io_chunk_size)
        {
            fprintf(stderr, "stress: partial write (supposedly, offset %ld size %d, written %zd)\n",
                    off, opts->io_chunk_size, st);
            exit(1);
        }

        off += opts->io_chunk_size;
    }
}

static int sequential = 0;

enum options
{
    OPT_FILESIZE = 1,
    OPT_TIME,
    OPT_IO_BLOCK_SIZE
};

const static struct option options[] = {
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {"threads", required_argument, NULL, 't'},
    {"sequential", no_argument, &sequential, 's'},
    {"file-size", required_argument, NULL, OPT_FILESIZE},
    {"time", required_argument, NULL, OPT_TIME},
    {"io-block-size", required_argument, NULL, OPT_IO_BLOCK_SIZE},
    {"direct", no_argument, &direct_io, 1},
    {"fsync", no_argument, &do_fsync, 1},
    {"fsync-dir", no_argument, &do_fsync_dir, 1},
    {}};

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

void usage(void)
{
    printf("Usage: %s [options] FILENAME\n"
           "    Stress I/O on a single file\n",
           program_invocation_short_name);
    printf("    --help                  Output this help message and exit\n"
           "    --version               Output the version information and exit\n"
           "    -t, --threads THREADS   Set the thread count (by default, the test is "
           "single-threaded)\n"
           "    -s, --sequential        Do IO sequentially on the file (incompatible with "
           "multi-threaded)\n"
           "    --file-size SIZE        Size of the file to create, in bytes (default = 4 MiB)\n"
           "    --time TIME             Time to run the test for (default = 10 seconds)\n"
           "    --io-block-size BLKSIZE Set the block size for I/O operations\n"
           "    --direct                Use O_DIRECT to do direct I/O and bypass the page cache\n"
           "    --fsync                 Do fsync() after writing the file\n"
           "    --fsync-dir             Do fsync() on the directory after creating the file\n\n"
           "If anything went wrong, exits with exit status 1.\n"
           "If everything looks to completed successfully, exits with 0.\n");
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage();
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
                usage();
                return opt == '?';
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
            case OPT_FILESIZE:
                // --file-size
                errno = 0;
                file_size = strtoul(optarg, NULL, 0);
                if (errno == ERANGE || file_size == 0)
                {
                    printf("iostress: File size number out of range [1, ULONG_MAX]\n");
                    return 1;
                }

                break;
            case OPT_TIME:
                errno = 0;
                timeout = strtoul(optarg, NULL, 0);
                if (errno == ERANGE || file_size == 0)
                {
                    printf("iostress: Timeout number out of range [1, ULONG_MAX]\n");
                    return 1;
                }

                break;
            case OPT_IO_BLOCK_SIZE:
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

    if (optind == argc)
    {
        warnx("Missing filename");
        usage();
        return 1;
    }

    srand(time(NULL));

    const char *filename = argv[optind];

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

    if (do_fsync)
    {
        if (fsync(fd) < 0)
            err(1, "fsync");
    }
}
