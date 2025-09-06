/*
 * Copyright (c) 2024 - 2025 Pedro Falcato
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

#define HPAGE_SIZE  PMD_SIZE
#define HPAGE_ORDER (PMD_SHIFT - PTE_SHIFT)

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

static int hugetlb_fault(struct vm_pf_context *ctx)
{
    struct folio *folio;
    struct mm_address_space *mm = ctx->entry->vm_mm;
    pmd_t *pmd;
    struct spinlock *lock;
    u64 phys;

    ctx->vpage &= -HPAGE_SIZE;
    folio = folio_alloc(HPAGE_ORDER, GFP_KERNEL);
    if (!folio)
        return -ENOMEM;

    pmd = ctx->pmd;
    lock = pmd_lockptr(mm, pmd);

    spin_lock(lock);
    CHECK(pmd != NULL);
    if (!pmd_none(*pmd))
    {
        /* Ruh roh. */
        goto err_unlock;
    }

    /* TODO: Pages can be cowed if they were forked. */

    phys = (u64) folio_to_phys(folio);
    /* Set mapcount to 1 (raw = 0). It will also consume our current folio reference. */
    __folio_reset_mapcount(folio, 0);
    set_pmd(pmd, pmd_mkpmd_huge(phys, calc_pgprot(phys, ctx->page_rwx)));
    increment_vm_stat(mm, resident_set_size, PMD_SIZE);
    spin_unlock(lock);
    return 0;
err_unlock:
    spin_unlock(lock);
    folio_put(folio);
    return -ENOMEM;
}

static bool hugetlb_may_split(struct vm_area_struct *vma, unsigned long addr)
{
    if (addr & (HPAGE_SIZE - 1))
        return false;
    return true;
}

const struct vm_operations hugetlb_vmops = {
    .fault_huge_pmd = hugetlb_fault,
    .may_split = hugetlb_may_split,
};

static const struct file_ops hugetlb_ops = {
    .find_free_area = hugetlb_find_free_area,
};

static const struct super_ops hugetlbfs_super_ops = {
    .shutdown = sb_generic_shutdown,
};

static ino_t next_ino;

__init void hugetlbfs_init(void)
{
    hugetlbfs_sb = kmalloc(sizeof(*hugetlbfs_sb), GFP_KERNEL);
    DCHECK(hugetlbfs_sb != NULL);
    superblock_init(hugetlbfs_sb, SB_FLAG_IN_MEMORY | SB_FLAG_NODIRTY);
    hugetlbfs_sb->s_ops = &hugetlbfs_super_ops;
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
    inode->inode.i_fops = &hugetlb_ops;
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

    struct dentry *dentry = dentry_create("<anon_hugetlb>", NULL, NULL, 0);
    if (!dentry)
        goto err1;

    filp->f_dentry = dentry;
    dget(dentry);
    return filp;

err1:
    kfree(ino);
    return NULL;
}
