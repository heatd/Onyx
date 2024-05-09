/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2024 Pedro Falcato */
#include <err.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>
#endif

static void usage(void)
{
    printf("Usage: trunctests PATH_TO_FILE\n"
           "       trunctests does truncation-related testing on a file\n");
}

static void do_trunc_tests(const char *filename);

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage();
        return 1;
    }

    do_trunc_tests(argv[1]);
}

static void fill_trunc_params(int fd, unsigned long *blksize, unsigned long *pagesize)
{
    /* Fetch the block size for the filesystem, and the page size while we're at it */
    struct statfs stafs;
    if (fstatfs(fd, &stafs) < 0)
        err(1, "fstatfs");
    *blksize = stafs.f_bsize;
    *pagesize = sysconf(_SC_PAGE_SIZE);
}

static void fill_file(int fd, unsigned int size)
{
    ssize_t res;
    char *buffer = malloc(size);
    if (!buffer)
        err(1, "malloc");
    /* Fill the file with a recognizable, relatively unique pattern */
    memset(buffer, 0xad, size);

    res = write(fd, buffer, size);
    if (res < 0)
        err(1, "write");
    if (res != size)
        errx(1, "write: short write (%zu bytes out of %zu)", (size_t) res, (size_t) size);
    free(buffer);
}

static sigjmp_buf jbuf;

static void sigbus_handler(int sig)
{
    siglongjmp(jbuf, 1);
}

static void test_sigbus_works(void *ptr, unsigned int filesize)
{
    if (sigsetjmp(jbuf, 1) == 1)
    {
        /* Success! */
        signal(SIGBUS, SIG_DFL);
        printf("Test SIGBUS works OK\n");
        return;
    }

    signal(SIGBUS, sigbus_handler);

    volatile int *p = (volatile int *) (ptr + filesize);
    *p;
    errx(1, "SIGBUS does not work on faults after EOF");
}

static void file_check_unmapped(int fd, unsigned int off, unsigned int bsize)
{
    uint64_t blk = off / bsize;

#ifdef FIBMAP
    unsigned int fibmap_blk = blk;
    if (ioctl(fd, FIBMAP, &fibmap_blk) == 0)
    {
        blk = fibmap_blk;
        goto check;
    }
#endif
    static int say_once = 0;
    if (say_once++ == 0)
        fprintf(stderr, "We failed to map the block, skipping...\n");
    return;
check:
    if (blk != 0)
        err(1, "Error: offset %u is still mapped to a real block (%llu), instead of a file hole\n",
            blk);
}

static void touch_mapping(void *ptr, unsigned int size, unsigned int pagesize)
{
    for (unsigned int i = 0; i < size; i += pagesize)
    {
        volatile uint8_t *ptr8 = (volatile uint8_t *) ptr;
        ptr8[i];
    }
}

static void truncation_test(int fd, void *ptr, unsigned int filesize, unsigned int pagesize,
                            unsigned int to_trunc, unsigned int bsize)
{
    ssize_t st;
    char buffer[to_trunc];
    unsigned int newsize = filesize - to_trunc;

    /* We're going to need this later (MAP_PRIVATE truncation test) */
    void *uncow = mmap(NULL, filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED)
        err(1, "mmap");
    void *cow = mmap(NULL, filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED)
        err(1, "mmap");

    touch_mapping(uncow, filesize, pagesize);
    touch_mapping(cow, filesize, pagesize);
    *(volatile int *) (cow + newsize + 4) = 10;

    if (ftruncate(fd, newsize) < 0)
        err(1, "ftruncate");

    if (to_trunc >= pagesize)
    {
        /* Check for a proper SIGBUS */
        if (sigsetjmp(jbuf, 1) == 0)
        {
            signal(SIGBUS, sigbus_handler);
            volatile int *p = (volatile int *) (ptr + newsize);
            *p;
            errx(1, "Access to bad page did not raise SIGBUS");
        }

        /* Success! */
        signal(SIGBUS, SIG_DFL);
    }

    /* Truncate it back to filesize */
    if (ftruncate(fd, filesize) < 0)
        err(1, "ftruncate");

    /* Check that the block is not mapped, if to_trunc is bsize aligned */
    if ((to_trunc % bsize) == 0)
        file_check_unmapped(fd, filesize - to_trunc, bsize);

    /* Make sure that 1) both read() and mmap agree on the contents and 2) the contents are
     * completely zeroed. Also test that un-CoW'd MAP_PRIVATE pages get shot down correctly (not
     * required by POSIX, but required by traditional MAP_PRIVATE implementation semantics), and
     * that CoW'd pages do not.
     */
    st = pread(fd, buffer, to_trunc, newsize);
    if (st < 0)
        err(1, "pread");
    if (st != to_trunc)
        errx(1, "pread partial read (%u out of %u bytes)", (unsigned int) st, to_trunc);
    if (memcmp(buffer, ptr + newsize, to_trunc))
        errx(1, "read() and mmap's contents don't match");
    for (unsigned int i = 0; i < to_trunc; i++)
    {
        if (buffer[i] != 0)
            errx(1, "truncate did not free pages/blocks correctly");
    }

    if (memcmp(buffer, uncow + newsize, to_trunc))
        errx(1, "read() and MAP_PRIVATE mmap contents don't match (rmap is broken?)");
#ifndef __linux__
    /* Okay, Linux doesn't seem to preserve CoW'd MAP_PRIVATE memory in this case. This is weird,
     * but seems to be allowed by POSIX. FreeBSD does the obvious, so does Onyx. */
    if (!memcmp(buffer, cow + newsize, to_trunc))
        errx(1, "read() and cow'd MAP_PRIVATE mmap contents match (rmap is broken?)");
#endif

    munmap(cow, filesize);
    munmap(uncow, filesize);

    /* Restore the pattern */
    memset(ptr + newsize, 0xad, to_trunc);
}

static void test_whole_page(int fd, void *ptr, unsigned int filesize, unsigned int pagesize,
                            unsigned int bsize)
{
    truncation_test(fd, ptr, filesize, pagesize, pagesize, bsize);
    printf("Whole page truncation OK\n");
}

static void test_partial_page(int fd, void *ptr, unsigned int filesize, unsigned int pagesize,
                              unsigned int bsize)
{
    truncation_test(fd, ptr, filesize, pagesize, pagesize / 2, bsize);
    printf("Partial page truncation OK\n");
    truncation_test(fd, ptr, filesize, pagesize, bsize / 2, bsize);
    printf("Partial block truncation (block size %u) OK\n", bsize);
}

static void do_trunc_tests(const char *filename)
{
    unsigned long blksize, pagesize;

    int fd = open(filename, O_RDWR | O_TRUNC | O_CREAT, 0644);
    if (fd < 0)
        err(1, "open");

    fill_trunc_params(fd, &blksize, &pagesize);

    /* Fill the file with 16 pages */
    unsigned int filesize = pagesize * 16;
    if (ftruncate(fd, filesize) < 0)
        err(1, "ftruncate");
    fill_file(fd, filesize);

    /* Map a little out of bounds, for SIGBUS testing */
    void *ptr = mmap(NULL, filesize + pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED)
        err(1, "mmap");
    /* Test 1: SIGBUS works before truncation */
    test_sigbus_works(ptr, filesize);
    touch_mapping(ptr, filesize, pagesize);

    /* Test 2: Whole page/block truncation */
    test_whole_page(fd, ptr, filesize, pagesize, blksize);

    /* Test 3: Partial page/block truncation */
    test_partial_page(fd, ptr, filesize, pagesize, blksize);
}
