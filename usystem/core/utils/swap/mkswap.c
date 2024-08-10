/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <uapi/swap.h>
#include <uapi/types.h>
#include <uuid/uuid.h>

const struct option long_options[] = {{"help", 0, NULL, 'h'},
                                      {"version", 0, NULL, 'v'},
                                      {"pagesize", required_argument, NULL, 'p'},
                                      {}};

void show_help(int flag)
{
    /* Return 1 if it was an invalid flag. */
    int ret = flag == '?';

    printf("Usage:\n   mkswap [options]\nOptions:\n"
           "   -h/--help                 print help and exit\n"
           "   -v/--version              print version and exit\n"
           "   -p/--pagesize [PAGESIZE]  Set the page size (by default, autodetected)\n");

    exit(ret);
}

void show_version()
{
    printf("Onyx mkswap from Onyx utils 20240805\n");
    exit(0);
}

int main(int argc, char **argv)
{
    int indexptr = 0;
    int page_size = sysconf(_SC_PAGE_SIZE);
    char flag;

    while ((flag = getopt_long(argc, argv, "vhp", long_options, &indexptr)) != -1)
    {
        switch (flag)
        {
            case '?':
            case 'h':
                show_help(flag);
                break;
            case 'v':
                show_version();
                break;
            case 'p':
                page_size = atoi(optarg);
                break;
        }
    }

    if (optind == argc)
        show_help('?');
    const char *path = argv[optind];

    int fd = open(path, O_RDWR);
    if (fd < 0)
        err(1, "%s", path);

    struct stat buf;
    if (fstat(fd, &buf) < 0)
        err(1, "fstat");
    if (S_ISBLK(buf.st_mode))
    {
        if (ioctl(fd, BLKGETSIZE64, &buf.st_size) < 0)
            err(1, "ioctl BLKGETSIZE64");
    }

    if (buf.st_size < MIN_SWAP_SIZE_PAGES * page_size)
        errx(1, "%s: given device must be at least %d bytes in size", path,
             MIN_SWAP_SIZE_PAGES * page_size);
    struct swap_super super = {};
    super.swp_magic = SWAP_MAGIC;
    super.swp_version = SWAP_VERSION_CURRENT;
    super.swp_pagesize = page_size;
    super.swp_nr_pages = buf.st_size / page_size;
    uuid_generate(super.swp_uuid);

    char str[UUID_STR_LEN];
    uuid_unparse_lower(super.swp_uuid, str);

    if (write(fd, &super, sizeof(super)) != sizeof(super))
        err(1, "%s: write failed", path);
    printf("Created swap space on %s, UUID %s, %llu pages, page size %u\n", path, str,
           (unsigned long long) super.swp_nr_pages, super.swp_pagesize);
    return 0;
}
