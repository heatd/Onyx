/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <onyx/file.h>
#include <onyx/readahead.h>
#include <onyx/types.h>

int sys_fadvise64(int fd, off_t offset, size_t len, int advice)
{
    struct file *file;
    int err;

    file = get_file_description(fd);
    if (!file)
        return -EBADF;

    err = -ESPIPE;
    if (S_ISFIFO(file->f_ino->i_mode))
        goto out;

    err = -EINVAL;
    if (!file->f_mapping)
        goto out;

    err = 0;
    switch (advice)
    {
        case POSIX_FADV_WILLNEED:
            do_force_readahead(file->f_mapping->ino, offset, len);
            break;
        default:
            err = -EINVAL;
            break;
    }

out:
    fd_put(file);
    return err;
}
