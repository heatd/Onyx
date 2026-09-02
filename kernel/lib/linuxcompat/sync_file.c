/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/anon_inode.h>
#include <onyx/mm/slab.h>

#include <linux/sync_file.h>

static unsigned int sync_file_ioctl(int request, void *argp, struct file *file)
{
    WARN_ON_ONCE(1);
    return -ENOTTY;
}

static short sync_file_poll(void *poll_file, short events, struct file *file)
{
    WARN_ON_ONCE(1);
    return POLLIN | POLLOUT | POLLHUP;
}

static void sync_file_release(struct file *file)
{
    struct sync_file *sf = file->private_data;

    kfree(sf);
}

static const struct file_ops sync_file_ops = {
    .ioctl = sync_file_ioctl,
    .poll = sync_file_poll,
    .release = sync_file_release,
};

struct sync_file *sync_file_create(struct dma_fence *fence)
{
    struct sync_file *sf;
    struct file *file;

    sf = kmalloc(sizeof(*sf), GFP_KERNEL);
    if (!sf)
        return NULL;

    file = anon_inode_getfile("sync_file", &sync_file_ops, sf, 0);
    if (IS_ERR_OR_NULL(file))
    {
        kfree(sf);
        return NULL;
    }

    sf->file = file;
    sf->flags = 0;
    memset(sf->user_name, 0, sizeof(sf->user_name));
    sf->fence = dma_fence_get(fence);
    init_wait_queue_head(&sf->wq);
    return sf;
}

struct dma_fence *sync_file_get_fence(int fd)
{
    struct dma_fence *fence;
    struct sync_file *sf;
    struct file *file;

    fence = NULL;
    file = get_file_description(fd);
    if (!file)
        return NULL;

    if (file->f_op != &sync_file_ops)
        goto out_put;
    sf = file->private_data;
    fence = dma_fence_get(sf->fence);
out_put:
    fd_put(file);
    return fence;
}

char *sync_file_get_name(struct sync_file *sync_file, char *buf, int len)
{
    if (sync_file->user_name[0])
        strscpy(buf, sync_file->user_name, len);
    else
        strscpy(buf, "placeholder-name", len);

    return buf;
}
