/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <dlfcn.h>
#include <err.h>
#include <fcntl.h>

#if 0
#if !defined(__onyx__) && !defined(__FreeBSD__)
__attribute__((weak)) void *fdlopen(int fd, int flags)
{
    errx(1, "fdlopen: Not implemented by the platform\n");
}
#endif
#endif

int main(int argc, char **argv)
{
    const char *solib = "libonyx.so";
    if (argc > 1)
        solib = argv[1];
    void *handle = dlopen(solib, RTLD_NOW);

    if (!handle)
        errx(1, "dlopen: %s", dlerror());

    dlclose(handle);

    int fd = open(argc > 1 ? solib : "/lib/libonyx.so", O_RDWR | O_CLOEXEC);

    if (fd < 0)
        err(1, "open");

    handle = fdlopen(fd, RTLD_NOW);

    if (!handle)
        errx(1, "fdlopen: %s", dlerror());

    return 0;
}
