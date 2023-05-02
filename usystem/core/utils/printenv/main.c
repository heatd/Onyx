/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_usage(void)
{
    printf("Usage: %s [options] [variable]...\n"
           "    Print environment variables\n",
           program_invocation_short_name);
    printf("    --help      Output this help message and exit\n"
           "    --version   Output the version information and exit\n"
           "    -0, --null  Output a null byte instead of a newline at the end of the line\n\n"
           "If all options were found, exits with 0. If an option was not found, exits with 1.\n"
           "If there was an error writing the options to standard output, exits with 2.\n");
}

void print_version(void)
{
    printf("%s 0.2 - Onyx utilities\n", program_invocation_short_name);
}

static int nullbyte;

const struct option options[] = {{"help", no_argument, NULL, 'h'},
                                 {"version", no_argument, NULL, 'v'},
                                 {"null", no_argument, &nullbyte, '0'},
                                 {}};

void parse_args(int argc, char *const *argv)
{
    int opt;
    int optindex = 0;
    while ((opt = getopt_long_only(argc, argv, "0h", options, &optindex)) != -1)
    {
        switch (opt)
        {
            case '0':
                nullbyte = 1;
                break;
            case 'h':
            case '?':
                print_usage();
                exit(opt == 'h' ? 0 : 2);
            case 'v':
                print_version();
                exit(EXIT_SUCCESS);
        }
    }
}

static void endl(void)
{
    if (putchar(nullbyte ? '\0' : '\n') < 0)
        exit(2);
}

int main(int argc, char **argv, char **envp)
{
    parse_args(argc, argv);

    /* if optind == argc, print every env var */
    if (optind == argc)
    {
        while (*envp)
        {
            if (printf("%s", *envp++) < 0)
                return 2;
            endl();
        }

        return 0;
    }

    int found_all = 1;

    for (int i = optind; i < argc; i++)
    {
        char *value = getenv(argv[i]);
        if (!value)
        {
            found_all = 0;
            continue;
        }

        if (printf("%s", value) < 0)
            return 2;
        endl();
    }

    return found_all ? 0 : 1;
}
