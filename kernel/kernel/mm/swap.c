/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define pr_fmt(fmt) "swap: " fmt
#include <stdio.h>

#include <onyx/buffer.h>
#include <onyx/err.h>
#include <onyx/file.h>
#include <onyx/maple_tree.h>
#include <onyx/mm/slab.h>
#include <onyx/namei.h>
#include <onyx/rcupdate.h>
#include <onyx/user.h>
#include <onyx/vfs.h>

#include <uapi/swap.h>

typedef __swap_block_t swap_block_t;

struct swap_extent
{
    u64 logical_block;
    u64 physical_block;
    u64 length;
};

struct swap_block_group
{
    u8 *start, *end;
    unsigned long nr_free;
    int smallest_bit_free;
    struct spinlock lock;
};

struct swap_area
{
    unsigned long refs;
    union {
        struct
        {
            struct file *file;
            int flags;
            int prio;
        };
        struct rcu_head rcu_head;
    };

    /* Points to the file's bdev (if a block device), or the partition itself. */
    struct blockdev *bdev;
    swap_block_t nr_pages;
    swap_block_t swap_off;

    struct maple_tree extents_tree;
    struct swap_block_group *block_groups;
    unsigned long nr_block_groups;

    u8 *swap_map;
};

static inline struct blockdev *blkdev_get_dev(struct file *f)
{
    return (struct blockdev *) f->f_ino->i_helper;
}

#define MAX_SWAP_AREAS 16

struct spinlock swap_areas_lock;
static struct swap_area *swap_areas[MAX_SWAP_AREAS];

/**
 * @brief Set the block device's block size
 *
 * @param bdev Block device
 * @param block_size Block size
 * @return 0 on success, negative error codes
 */
int block_set_bsize(struct blockdev *bdev, unsigned int block_size);

static int parse_super(struct swap_area *swp)
{
    /* Swap is read and written to in page units */
    int err = block_set_bsize(swp->bdev, PAGE_SIZE);
    if (err < 0)
        return err;

    struct block_buf *bb = bdev_read_block(swp->bdev, 0);
    if (!bb)
        return -EIO;

    struct swap_super *super = block_buf_data(bb);

    err = -EINVAL;
    if (super->swp_magic != SWAP_MAGIC)
    {
        pr_err("Bad swap magic %llx\n", (unsigned long long) super->swp_magic);
        goto out;
    }

    if (super->swp_flags & SWP_FLAG_BAD)
    {
        pr_err("Bad swap partition\n");
        goto out;
    }

    if (super->swp_pagesize != PAGE_SIZE)
    {
        pr_err("Configured page size (%u) != the system's page size (%lu)\n", super->swp_pagesize,
               PAGE_SIZE);
        goto out;
    }

    if (super->swp_nr_pages <= MIN_SWAP_SIZE_PAGES)
    {
        pr_err("Configured swap area is too small (%llu pages, should be %d)\n",
               (unsigned long long) super->swp_nr_pages, MIN_SWAP_SIZE_PAGES);
        goto out;
    }

    swp->nr_pages = super->swp_nr_pages - MIN_SWAP_SIZE_PAGES;
    swp->swap_off = MIN_SWAP_SIZE_PAGES;
    err = 0;
out:
    block_buf_put(bb);
    return err;
}

/**
 * @brief Destroy a partially constructed swap area
 *
 * @param sa Swap area
 */
static void swap_area_destroy_early(struct swap_area *sa)
{
    /* No need to use RCU for any of this stuff here, we haven't exposed this swap area yet */
    unsigned long index = 0;
    struct swap_extent *se;
    mt_for_each (&sa->extents_tree, se, index, -1UL)
        kfree(se);

    mtree_destroy(&sa->extents_tree);

    if (sa->block_groups)
        vfree(sa->block_groups,
              vm_size_to_pages(sa->nr_block_groups * sizeof(struct swap_block_group)));
    if (sa->swap_map)
        vfree(sa->swap_map, vm_size_to_pages(sa->nr_pages));

    if (sa->file)
        fd_put(sa->file);
    kfree(sa);
}

static int swap_setup_map(struct swap_area *sa)
{
    sa->swap_map =
        vmalloc(vm_size_to_pages(sa->nr_pages), VM_TYPE_REGULAR, VM_READ | VM_WRITE, GFP_KERNEL);
    if (!sa->swap_map)
    {
        pr_err("Failed to allocate a %lukB sized swap_map\n", sa->nr_pages / 1024);
        return -ENOMEM;
    }

    /* TODO: Sizing block groups is... weird. We'll try to size them like a filesystem for now. But
     * it's not ideal concurrency-wise if we have a smaller swap. */
#define MAX_BLOCK_GROUP_SIZE (PAGE_SIZE / 2)
    sa->nr_block_groups = sa->nr_pages / MAX_BLOCK_GROUP_SIZE;
    if (sa->nr_pages % MAX_BLOCK_GROUP_SIZE)
        sa->nr_block_groups++;

    sa->block_groups =
        vmalloc(vm_size_to_pages(sa->nr_block_groups * sizeof(struct swap_block_group)),
                VM_TYPE_REGULAR, VM_WRITE | VM_READ, GFP_KERNEL);
    if (!sa->block_groups)
    {
        pr_err("Failed to allocate an %lukB sized array of swap_block_groups\n",
               sa->nr_block_groups * sizeof(struct swap_block_group) / 1024);
        return -ENOMEM;
    }

    for (unsigned long i = 0, start = 0; i < sa->nr_block_groups;
         i++, start += MAX_BLOCK_GROUP_SIZE)
    {
        struct swap_block_group *bg = &sa->block_groups[i];
        unsigned long size = min(sa->nr_pages - start, MAX_BLOCK_GROUP_SIZE);
        bg->start = sa->swap_map + start;
        bg->end = bg->start + size;
        bg->nr_free = size;
        bg->smallest_bit_free = 0;
        spinlock_init(&bg->lock);
    }

    return 0;
}

static int swap_install(struct swap_area *sa)
{
    int err = 1;
    spin_lock(&swap_areas_lock);

    for (int i = 0; i < MAX_SWAP_AREAS; i++)
    {
        if (!swap_areas[i])
        {
            swap_areas[i] = sa;
            err = 0;
            break;
        }
    }

    spin_unlock(&swap_areas_lock);

    if (err)
        pr_err("Failed to install swap area: limit reached\n");
    return err ? -ESRCH : 0;
}

static int do_swapon(struct file *swapfile, int flags)
{
    int err = -ENOMEM, prio;
    unsigned long nr_pages;
    struct swap_area *swp = kmalloc(sizeof(*swp), GFP_KERNEL);
    if (!swp)
    {
        fd_put(swapfile);
        return err;
    }

    memset(swp, 0, sizeof(*swp));
    swp->refs = 1;
    swp->file = swapfile;
    swp->flags = flags;
    swp->bdev = blkdev_get_dev(swapfile);
    swp->extents_tree = (struct maple_tree) MTREE_INIT(swp->extents_tree, MT_FLAGS_USE_RCU);

    /* Set up a simple extent covering the whole thing, for block devices */
    struct swap_extent *extent = kmalloc(sizeof(*extent), GFP_KERNEL);
    if (!extent)
    {
        err = -ENOMEM;
        goto out_err;
    }

    extent->length = -1ULL;
    extent->logical_block = 0;
    extent->physical_block = 0;
    err = mtree_insert_range(&swp->extents_tree, 0, -1UL, extent, GFP_KERNEL);
    if (err < 0)
        goto out_err;

    err = parse_super(swp);
    if (err < 0)
        goto out_err;

    err = swap_setup_map(swp);
    if (err < 0)
        goto out_err;

    /* Read it before installing, since we lose the swap_area's ownership */
    prio = swp->prio;
    nr_pages = swp->nr_pages;

    err = swap_install(swp);
    if (err < 0)
        goto out_err;

    pr_info("Installed swap area with %lukB, priority %d\n", nr_pages * PAGE_SIZE / 1024, prio);
    return 0;
out_err:
    swap_area_destroy_early(swp);
    return err;
}

#define VALID_SWAPON_FLAGS 0

int sys_swapon(const char *upath, int flags)
{
    int err = 0;

    if (flags & ~VALID_SWAPON_FLAGS)
        return -EINVAL;

    const char *path = strcpy_from_user(upath);
    if (!path)
        return -ENOMEM;

    /* We use O_EXCL to _possibly_ grab the bdev atomically  */
    struct file *file = c_vfs_open(AT_FDCWD, path, O_RDWR | O_EXCL, 0);
    if (IS_ERR(file))
    {
        err = PTR_ERR(file);
        goto err;
    }

    if (!S_ISBLK(file->f_ino->i_mode))
    {
        pr_err("Attempted to use %s as a swap area, which is not yet supported. Only block "
               "devices are supported yet.\n",
               path);
        err = -EINVAL;
        fd_put(file);
        goto err;
    }

    return do_swapon(file, flags);
err:
    free((void *) path);
    return err;
}

int sys_swapoff(const char *upath)
{
    return -ENOSYS;
}
