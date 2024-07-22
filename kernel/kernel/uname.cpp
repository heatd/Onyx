/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include <onyx/uname.h>
#include <onyx/vm.h>

const char *network_gethostname();
void network_sethostname(const char *);

int sys_uname(struct utsname *ubuf)
{
    struct utsname buf = {};
    strcpy(buf.sysname, OS_NAME);
    strcpy(buf.release, OS_RELEASE);
    strcpy(buf.version, OS_VERSION);
    if (strlen(KERNEL_TAGS) != 0)
    {
        strcat(buf.version, "-");
        strcat(buf.version, KERNEL_TAGS);
    }

    strcpy(buf.machine, OS_MACHINE);

    strncpy(buf.nodename, network_gethostname(), sizeof(buf.nodename) - 1);
    buf.nodename[sizeof(buf.nodename) - 1] = '\0';
    if (copy_to_user(ubuf, &buf, sizeof(struct utsname)) < 0)
        return -EFAULT;
    return 0;
}
