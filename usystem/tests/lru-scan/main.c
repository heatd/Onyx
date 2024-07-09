// SPDX-License-Identifier: GPL-2.0-only
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage: lru-scan [path to file]\n");
        return 1;
    }

    int pagesz = getpagesize();
    const char *file = argv[1];
    int fd = open(file, O_RDONLY);
    if (fd < 0)
        err(1, "%s", file);

    struct stat buf;
    if (fstat(fd, &buf) < 0)
        err(1, "fstat");
    if (S_ISBLK(buf.st_mode))
    {
        if (ioctl(fd, BLKGETSIZE64, &buf.st_size) < 0)
            err(1, "ioctl BLKGETSIZE64");
    }

    /* Scan the whole file linearly, in an mmap. This tests if reclamation works properly for mapped
     * pages. */
    void *ptr = mmap(NULL, buf.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED)
        err(1, "mmap");
    for (size_t i = 0; i < (size_t) buf.st_size / pagesz; i++)
    {
        volatile uint8_t *ptr8 = ptr + (i * pagesz);
        *ptr8;
    }
}
