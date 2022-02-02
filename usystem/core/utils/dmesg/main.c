/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <stdio.h>
#include <stdlib.h>

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int size = (int)syscall(SYS_syslog, 10, NULL, -1);
    char *buf = malloc(size);
    if (!buf)
    {
        perror("dmesg");
        return 1;
    }
    syscall(SYS_syslog, 2, buf, size);
    printf("%s\n", buf);

    return 0;
}
