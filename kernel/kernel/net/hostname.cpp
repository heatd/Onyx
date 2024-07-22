/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include <onyx/net/network.h>
#include <onyx/types.h>
#include <onyx/vm.h>

/* FIXME: 98% sure there's a race condition here, TOFIX */

int sys_sethostname(const void *name, size_t len)
{
    if (len > 65)
        return -EINVAL;

    if ((ssize_t) len < 0)
        return -EINVAL;

    /* We need to copy the name, since the user pointer isn't safe */
    char *hostname = static_cast<char *>(malloc(len + 1));
    if (!hostname)
        return -ENOMEM;

    memset(hostname, 0, len + 1);
    if (copy_from_user(hostname, name, len) < 0)
    {
        free(hostname);
        return -EFAULT;
    }

    network_sethostname(hostname);

    return 0;
}
