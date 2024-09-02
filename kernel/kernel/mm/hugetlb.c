/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/compiler.h>
#include <onyx/file.h>
#include <onyx/inode.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/pgtable.h>
#include <onyx/superblock.h>
#include <onyx/vm.h>
#include <onyx/vm_fault.h>

#define HPAGE_SIZE PMD_SIZE
static struct superblock *hugetlbfs_sb;

struct hugetlb_inode
{
    struct inode inode;
};

static int hugetlb_find_free_area(struct vma_iterator *vmi, unsigned long min, size_t size,
                                  struct file *file)
{
    return vm_find_free_area(vmi, min, size, HPAGE_SIZE);
}

unsigned int hugetlb_pagesize(void)
{
    return HPAGE_SIZE;
}

const struct vm_operations hugetlb_vmops = {};

static const struct file_ops hugetlb_ops = {
    .find_free_area = hugetlb_find_free_area,
};

static ino_t next_ino;

__init void hugetlbfs_init(void)
{
    hugetlbfs_sb = kmalloc(sizeof(*hugetlbfs_sb), GFP_KERNEL);
    DCHECK(hugetlbfs_sb != NULL);
    superblock_init(hugetlbfs_sb);
}

struct hugetlb_inode *hugetlb_new_inode(size_t size)
{
    struct hugetlb_inode *inode = kmalloc(sizeof(*inode), GFP_KERNEL);
    if (!inode)
        return NULL;
    if (inode_init(&inode->inode, true) < 0)
    {
        free(inode);
        return NULL;
    }

    inode->inode.i_sb = hugetlbfs_sb;
    inode->inode.i_size = size;
    inode->inode.i_fops = (struct file_ops *) &hugetlb_ops;
    inode->inode.i_inode = __atomic_add_fetch(&next_ino, 1, __ATOMIC_RELAXED);
    return inode;
}

struct file *hugetlb_new_file(size_t size)
{
    /* TODO: WIP error paths */
    struct hugetlb_inode *ino = hugetlb_new_inode(size);
    if (!ino)
        goto err1;

    struct file *filp = inode_to_file(&ino->inode);
    if (!filp)
        return NULL;

    struct dentry *dentry = dentry_create("<hugetlb>", NULL, NULL, 0);
    if (!dentry)
        goto err1;

    filp->f_dentry = dentry;
    return filp;

err1:
    kfree(ino);
    return NULL;
}
