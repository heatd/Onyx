/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _IOCTX_H
#define _IOCTX_H

#include <sys/types.h>

#include <onyx/file.h>
#include <onyx/mutex.h>
#include <onyx/vfs.h>

#define FDS_PER_LONG            (sizeof(unsigned long) * 8)
#define FILE_DESCRIPTOR_GROW_NR (FDS_PER_LONG)

struct ioctx
{
    /* Current working directory */
    spinlock cwd_lock{};
    file *cwd{};
    spinlock fdlock{};
    struct file **file_desc{};
    unsigned int file_desc_entries{};
    unsigned long *cloexec_fds{};
    unsigned long *open_fds{};
    mode_t umask{};
};

#endif
