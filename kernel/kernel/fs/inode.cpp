/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>

#include <onyx/block.h>
#include <onyx/buffer.h>
#include <onyx/dev.h>
#include <onyx/file.h>
#include <onyx/fnv.h>
#include <onyx/gen/trace_writeback.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/pagecache.h>
#include <onyx/panic.h>
#include <onyx/rwlock.h>
#include <onyx/scoped_lock.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>
#include <onyx/wait.h>

#include <onyx/hashtable.hpp>
#include <onyx/list.hpp>

fnv_hash_t inode_hash(inode &ino)
{
    auto h = fnv_hash(&ino.i_dev, sizeof(dev_t));
    h = fnv_hash_cont(&ino.i_inode, sizeof(ino_t), h);
    return h;
}

fnv_hash_t inode_hash(dev_t dev, ino_t ino)
{
    auto h = fnv_hash(&dev, sizeof(dev_t));
    return fnv_hash_cont(&ino, sizeof(ino_t), h);
}

constexpr size_t inode_hashtable_size = 512;

static cul::hashtable2<inode, inode_hashtable_size, fnv_hash_t, inode_hash> inode_hashtable;
static struct spinlock inode_hashtable_locks[inode_hashtable_size];

int pipe_do_fifo(inode *ino);

struct slab_cache *inode_cache;

__init static void inode_cache_init()
{
    inode_cache = kmem_cache_create("inode", sizeof(struct inode), 0, KMEM_CACHE_HWALIGN, nullptr);
    CHECK(inode_cache != nullptr);
}

struct inode *inode_create(bool is_cached)
{
    struct inode *inode = (struct inode *) kmem_cache_alloc(inode_cache, GFP_KERNEL);
    if (!inode)
        return nullptr;

    if (inode_init(inode, is_cached) < 0)
    {
        kmem_cache_free(inode_cache, inode);
        return nullptr;
    }

    return inode;
}

int inode_special_init(struct inode *ino)
{
    if (S_ISBLK(ino->i_mode) || S_ISCHR(ino->i_mode))
    {
        gendev *dev = S_ISBLK(ino->i_mode) ? (gendev *) dev_find_block(ino->i_rdev)
                                           : (gendev *) dev_find_chr(ino->i_rdev);
        if (!dev)
            return -ENODEV;

        ino->i_fops = const_cast<file_ops *>(dev->fops());
        ino->i_helper = dev->private_;
        if (S_ISBLK(ino->i_mode))
        {
            struct blockdev *bdev = (struct blockdev *) dev->private_;
            ino->i_pages = bdev->b_ino->i_pages;
            vmo_ref(ino->i_pages);
        }
    }
    else if (S_ISFIFO(ino->i_mode))
    {
        return pipe_do_fifo(ino);
    }

    return 0;
}

void inode_ref(struct inode *ino)
{
    __atomic_add_fetch(&ino->i_refc, 1, __ATOMIC_ACQUIRE);
#if 0
	if(ino->i_inode == 3549)
		printk("inode_ref(%lu) from %p\n", ino->i_refc, __builtin_return_address(0));
#endif
}

void inode_destroy_page_caches(struct inode *inode)
{
    if (inode->i_pages)
        vmo_unref(inode->i_pages);
}

ssize_t inode_sync(struct inode *inode)
{
    if (!inode->i_pages)
        return 0;

    unsigned int flags;

    {
        scoped_lock g{inode->i_lock};
        flags = inode->i_flags;
    }

    if (flags & I_DATADIRTY)
    {
        struct writepages_info info;
        info.start = 0;
        info.end = ULONG_MAX;
        info.flags = WRITEPAGES_SYNC;
        int st = inode->i_fops->fsyncdata ? inode->i_fops->fsyncdata(inode, &info) : 0;
        if (st < 0)
            return st;
    }

    if (flags & I_DIRTY)
    {
        int st = 0;
        if (inode->i_sb && inode->i_sb->flush_inode)
            st = inode->i_sb->flush_inode(inode, true);
        if (st < 0)
            return st;
    }

    return 0;
}

bool inode_is_cacheable(struct inode *file);

/**
 * @brief Attempt to remove ourselves from wbdev IO queues.
 * This function sleeps if I_WRITEBACK is set. The inode *may* be dirty after the function
 * completes.
 *
 * @param inode Inode to remove
 */
static void inode_wait_for_wb_and_remove(struct inode *inode)
{
    /* Attempt to remove ourselves from wbdev IO queues. This function sleeps if I_WRITEBACK. */
    spin_lock(&inode->i_lock);
    for (;;)
    {
        if (!(inode->i_flags & (I_WRITEBACK | I_DIRTYALL)))
            break;
        if (inode->i_flags & I_WRITEBACK)
        {
            spin_unlock(&inode->i_lock);
            /* Sleep and try again */
            inode_wait_writeback(inode);
            spin_lock(&inode->i_lock);
            continue;
        }

        if (inode->i_flags & I_DIRTYALL)
        {
            /* Drop the inode lock, lock the wbdev, lock the inode again */
            flush::writeback_dev *wbdev = bdev_get_wbdev(inode);
            unsigned int old_flags = inode->i_flags;
            spin_unlock(&inode->i_lock);
            wbdev->lock();
            spin_lock(&inode->i_lock);

            if (inode->i_flags != old_flags)
            {
                /* Drop the wbdev lock and spin again */
                wbdev->unlock();
                continue;
            }

            wbdev->remove_inode(inode);
            wbdev->unlock();
            break;
        }
    }

    spin_unlock(&inode->i_lock);
}

void inode_release(struct inode *inode)
{
    bool should_die = inode_get_nlink(inode) == 0;
    // printk("Should die %u\n", should_die);
    if (inode->i_flags & I_HASHED)
    {
        CHECK(inode->i_sb != nullptr);

        /* Remove the inode from its superblock and the inode cache */
        superblock_remove_inode(inode->i_sb, inode);
    }

    inode->set_evicting();

    inode_wait_for_wb_and_remove(inode);
    inode_sync(inode);
    {
        /* Clear dirty/writeback */
        scoped_lock g{inode->i_lock};
        inode->i_flags &= ~(I_DIRTYALL | I_WRITEBACK);
    }

    /* Note that we require kill_inode to be called before close, at least for now,
     * because close may very well free resources that are needed to free the inode.
     * This happens, for example, in ext2.
     */
    struct superblock *sb = inode->i_sb;

    if (should_die && sb && sb->kill_inode)
    {
        /* TODO: Handle failures? */
        sb->kill_inode(inode);
    }

    DCHECK((inode->i_flags & (I_DIRTYALL | I_WRITEBACK)) == 0);

    /* Destroy the page cache *after* kill inode, since kill_inode might need to access the vmo */
    inode_destroy_page_caches(inode);

    if (inode->i_fops->close != nullptr)
        inode->i_fops->close(inode);

    /* Note: We use kfree here, and not kmem_cache_free, because <inode> in some filesystems is not
     * allocated by inode_create.
     */
    kfree(inode);
}

void inode_unref(struct inode *ino)
{
    unsigned long refs = __atomic_sub_fetch(&ino->i_refc, 1, __ATOMIC_RELEASE);
    // printk("unref %p(ino nr %lu) - refs %lu\n", ino, ino->i_inode, refs);

    if (refs == 0 && inode_should_die(ino))
    {
        inode_release(ino);
    }
}

struct inode *superblock_find_inode(struct superblock *sb, ino_t ino_nr)
{
    auto hash = inode_hash(sb->s_devnr, ino_nr);

    auto index = inode_hashtable.get_hashtable_index(hash);

restart:

    scoped_lock g{inode_hashtable_locks[index]};

    auto _l = inode_hashtable.get_hashtable(index);

    list_for_every (_l)
    {
        auto ino = container_of(l, inode, i_hash_list_node);

        if (ino->i_dev == sb->s_devnr && ino->i_inode == ino_nr)
        {
            if (ino->i_flags & I_FREEING)
            {
                g.unlock();
                wait_for(
                    &ino->i_flags, [](void *addr) -> bool { return true; }, WAIT_FOR_FOREVER, 0);
                // Wait for the freeing to happen, then restart the lookup
                goto restart;
            }

            inode_ref(ino);
            return ino;
        }
    }

    g.keep_locked();

    return nullptr;
}

static inline void i_set_hashed(struct inode *inode)
{
    spin_lock(&inode->i_lock);
    DCHECK((inode->i_flags & I_HASHED) == 0);
    inode->i_flags |= I_HASHED;
    spin_unlock(&inode->i_lock);
}

static inline void i_unhash(struct inode *inode)
{
    spin_lock(&inode->i_lock);
    DCHECK(inode->i_flags & I_HASHED);
    inode->i_flags &= ~I_HASHED;
    spin_unlock(&inode->i_lock);
}

void superblock_add_inode_unlocked(struct superblock *sb, struct inode *inode)
{
    fnv_hash_t hash = inode_hash(sb->s_devnr, inode->i_inode);
    size_t index = inode_hashtable.get_hashtable_index(hash);
    struct list_head *head = inode_hashtable.get_hashtable(index);

    MUST_HOLD_LOCK(&inode_hashtable_locks[index]);

    list_add_tail(&inode->i_hash_list_node, head);

    scoped_lock g{sb->s_ilock};
    list_add_tail(&inode->i_sb_list_node, &sb->s_inodes);
    __atomic_add_fetch(&sb->s_ref, 1, __ATOMIC_ACQUIRE);

    i_set_hashed(inode);

    spin_unlock(&inode_hashtable_locks[index]);
}

/* Should only be used when creating new inodes(so we're sure that they don't exist). */
void superblock_add_inode(struct superblock *sb, struct inode *inode)
{
    auto hash = inode_hash(sb->s_devnr, inode->i_inode);
    auto index = inode_hashtable.get_hashtable_index(hash);
    scoped_lock g{inode_hashtable_locks[index]};
    superblock_add_inode_unlocked(sb, inode);

    // Was already unlocked
    g.keep_locked();
}

void superblock_remove_inode(struct superblock *sb, struct inode *inode)
{
    fnv_hash_t hash = inode_hash(sb->s_devnr, inode->i_inode);
    size_t index = inode_hashtable.get_hashtable_index(hash);

    scoped_lock g1{inode_hashtable_locks[index]};
    scoped_lock g2{sb->s_ilock};

    list_remove(&inode->i_sb_list_node);
    list_remove(&inode->i_hash_list_node);

    i_unhash(inode);

    __atomic_sub_fetch(&sb->s_ref, 1, __ATOMIC_RELAXED);
}

void superblock_kill(struct superblock *sb)
{
    list_for_every_safe (&sb->s_inodes)
    {
        struct inode *ino = container_of(l, inode, i_sb_list_node);

        close_vfs(ino);
    }
}

void inode_unlock_hashtable(struct superblock *sb, ino_t ino_nr)
{
    auto hash = inode_hash(sb->s_devnr, ino_nr);

    auto index = inode_hashtable.get_hashtable_index(hash);

    spin_unlock(&inode_hashtable_locks[index]);
}

int sys_fsync(int fd)
{
    auto_file f;
    if (f.from_fd(fd) < 0)
    {
        return -EBADF;
    }

    /* TODO: Same problem as inode_sync, return errors. */
    inode_sync(f.get_file()->f_ino);

    return 0;
}

int sys_fdatasync(int fd)
{
    auto_file f;
    if (f.from_fd(fd) < 0)
        return -EBADF;
    inode_sync(f.get_file()->f_ino);
    return 0;
}

void inode_add_hole_in_page(struct page *page, size_t page_offset, size_t end_offset) REQUIRES(page)
{
    page_wait_writeback(page);
    page_remove_block_buf(page, page_offset, end_offset);
    uint8_t *p = (uint8_t *) PAGE_TO_VIRT(page) + page_offset;
    memset(p, 0, end_offset - page_offset);
}

int inode_truncate_range(struct inode *inode, size_t start, size_t end)
{
    bool start_misaligned = start & (PAGE_SIZE - 1);
    bool end_misaligned = end & (PAGE_SIZE - 1);
    auto start_aligned = cul::align_down2(start, PAGE_SIZE);
    auto end_aligned = cul::align_down2(end, PAGE_SIZE);

    int st = vmo_punch_range(inode->i_pages, start, end - start);

    if (st < 0)
        return st;

    struct page *page = nullptr;

    /* That last statement is to make sure we don't try and insert a hole in the same page twice */
    if (start_misaligned && start_aligned != end_aligned)
    {
        /* Don't try to populate it */
        auto vmo_st = vmo_get(inode->i_pages, start_aligned, 0, &page);

        if (vmo_st == VMO_STATUS_OK)
        {
            lock_page(page);
            inode_add_hole_in_page(page, start - start_aligned, PAGE_SIZE);
            unlock_page(page);
            page_unref(page);
        }
    }

    if (end_misaligned)
    {
        /* Don't try to populate it */
        auto vmo_st = vmo_get(inode->i_pages, end_aligned, 0, &page);

        if (vmo_st == VMO_STATUS_OK)
        {
            /* TODO: I don't think the end here is correct for file hole cases, TOFIX */
            lock_page(page);
            inode_add_hole_in_page(page, end - end_aligned, PAGE_SIZE);
            unlock_page(page);
            page_unref(page);
        }
    }

    return 0;
}

static void inode_evict(inode *ino)
{
    inode_unref(ino);
    wake_address(&ino->i_flags);
}

cul::atomic_size_t evicted_inodes = 0;

/**
 * @brief Trim the inode cache
 *
 */
void inode_trim_cache()
{
    struct list_head to_evict = LIST_HEAD_INIT(to_evict);
    for (size_t i = 0; i < inode_hashtable_size; i++)
    {
        scoped_lock g{inode_hashtable_locks[i]};
        auto ht = inode_hashtable.get_hashtable(i);

        list_for_every_safe (ht)
        {
            auto ino = container_of(l, inode, i_hash_list_node);

            if (ino->i_refc == 0)
            {
                scoped_lock g2{ino->i_lock};

                if (ino->i_flags & I_FREEING)
                    continue; // Already being freed

                // Evictable, so evict
                {
                    scoped_lock g3{ino->i_sb->s_ilock};
                    list_remove(&ino->i_sb_list_node);
                }

                evicted_inodes++;
                ino->set_evicting();
                list_add_tail(&ino->i_sb_list_node, &to_evict);
            }
        }
    }

    list_for_every_safe (&to_evict)
    {
        auto ino = container_of(l, inode, i_sb_list_node);

        inode_evict(ino);
    }
}

void inode::set_evicting()
{
    scoped_lock g{i_lock};
    i_flags |= I_FREEING;
}

int noop_prepare_write(struct inode *ino, struct page *page, size_t page_off, size_t offset,
                       size_t len)
{
    return 0;
}

void inode_wait_writeback(struct inode *ino)
{
    spin_lock(&ino->i_lock);
    if (!(ino->i_flags & I_WRITEBACK))
    {
        spin_unlock(&ino->i_lock);
        return;
    }

    spin_unlock(&ino->i_lock);

    wait_for(
        ino,
        [](void *_ino) -> bool {
            struct inode *ino_ = (struct inode *) _ino;
            scoped_lock g{ino_->i_lock};
            return !(ino_->i_flags & I_WRITEBACK);
        },
        WAIT_FOR_FOREVER, 0);
}

bool inode_no_dirty(struct inode *ino, unsigned int flags)
{
    if (!ino->i_sb)
        return true;
    if (!(ino->i_sb->s_flags & SB_FLAG_NODIRTY))
        return false;

    /* If NODIRTY, check if we are a block device, and that we are dirtying pages */
    if (S_ISBLK(ino->i_mode))
        return !(flags & I_DATADIRTY);
    return true;
}

void inode_mark_dirty(struct inode *ino, unsigned int flags)
{
    /* FIXME: Ugh, leaky abstractions... */
    if (inode_no_dirty(ino, flags))
        return;

    DCHECK(flags & I_DIRTYALL);

    /* Already dirty */
    if ((ino->i_flags & flags) == flags)
        return;

    auto dev = bdev_get_wbdev(ino);
    dev->lock();
    spin_lock(&ino->i_lock);

    unsigned int old_flags = ino->i_flags;

    ino->i_flags |= flags;
    trace_wb_dirty_inode(ino->i_inode, ino->i_dev);

    /* The writeback code will take care of redirtying if need be */
    if (!(old_flags & (I_WRITEBACK | I_DIRTYALL)))
        dev->add_inode(ino);

    spin_unlock(&ino->i_lock);
    dev->unlock();
}
