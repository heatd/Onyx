/*
 * Copyright (c) 2017-2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

void print_usage()
{
    std::printf(
        "Usage: yes [STRING(s)]\nor yes OPTION\nRepeatedly output a string, or yes by default.\n");
    std::printf("\t--help: Output this help message and exit\n\t--version: Output the version "
                "information and exit\n");
    std::exit(0);
}

void print_version()
{
    std::printf("yes - Onyx utils 0.4\n");
    std::exit(0);
}

int main(int argc, char **argv)
{
    std::string str;

    // We're going to iterate through options, look at them and, if they're a string, append them,
    // else, handle the option through our really budget getopt.

    for (int i = 1; i < argc; i++)
    {
        const char *arg = argv[i];
        if (!strcmp(argv[i], "--help"))
            print_usage();
        else if (!strcmp(argv[i], "--version"))
            print_version();

        // If we have something in the string, add a space
        if (!str.empty())
            str.append(" ");
        str.append(argv[i]);
    }

    // We had no string arguments, just print y
    if (str.empty())
        str.append("y");

    while (true)
        std::printf("%s\n", str.c_str());

    return 0;
}
