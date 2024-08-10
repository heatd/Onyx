/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/swap.h>

void show_help(int flag)
{
    /* Return 1 if it was an invalid flag. */
    int ret = flag == '?';

    printf("Usage:\n   swapon [options] [SWAPFILE]\nOptions:\n"
           "   -h/--help                 print help and exit\n"
           "   -v/--version              print version and exit\n");
    exit(ret);
}

void show_version()
{
    printf("Onyx swapon from Onyx utils 20240805\n");
    exit(0);
}

const struct option long_options[] = {
    {"help", 0, NULL, 'h'},
    {"version", 0, NULL, 'v'},
    {},
};

int main(int argc, char **argv)
{
    int indexptr = 0;
    char flag;

    while ((flag = getopt_long(argc, argv, "vh", long_options, &indexptr)) != -1)
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
        }
    }

    if (optind == argc)
        show_help('?');

    if (swapon(argv[optind], 0) < 0)
        err(1, "swapon");
    return 0;
}
