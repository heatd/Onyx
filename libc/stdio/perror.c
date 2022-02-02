/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

void perror(const char *error_msg)
{
    const char *error = (const char *)strerror(errno);
    if (error_msg && *error_msg != '\0')
        printk("%s: %s\n", error_msg, error);
    else
        printk("%s\n", error);
}
