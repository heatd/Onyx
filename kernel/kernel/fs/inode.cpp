/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdio.h>

#include <onyx/buffer.h>
#include <onyx/dev.h>
#include <onyx/file.h>
#include <onyx/fnv.h>
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
    scoped_mutex g{inode->i_pages->page_lock};

#if 0
    // TODO: This sucks
    inode->i_pages->for_every_page([&](struct page *page, unsigned long off) -> bool {
        struct page_cache_block *b = page->cache;

        if (page->flags & PAGE_FLAG_DIRTY)
        {
            flush_sync_one(&b->fobj);
        }

        return true;
    });
#endif

    return 0;
}

bool inode_is_cacheable(struct inode *file);

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

    /*if (inode->i_flags & INODE_FLAG_DIRTY)
        flush_remove_inode(inode);*/

    if (inode_is_cacheable(inode))
        inode_sync(inode);

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

    /* Destroy the page cache *after* kill inode, since kill_inode might need to access the vmo */
    inode_destroy_page_caches(inode);

    if (inode->i_fops->close != nullptr)
        inode->i_fops->close(inode);

    free(inode);
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
            if (ino->i_flags & INODE_FLAG_FREEING)
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

void inode_add_hole_in_page(struct page *page, size_t page_offset, size_t end_offset)
{
#if 0
	printk("adding hole in page, page offset %lu, end offset %lu\n", page_offset, end_offset);
    struct page_cache_block *b = page->cache;
    if (page->flags & PAGE_FLAG_DIRTY)
    {
        flush_sync_one(&b->fobj);
    }
#endif

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
            inode_add_hole_in_page(page, start - start_aligned, PAGE_SIZE);
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
            inode_add_hole_in_page(page, end - end_aligned, PAGE_SIZE);
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

                if (ino->i_flags & INODE_FLAG_FREEING)
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
    i_flags |= INODE_FLAG_FREEING;
}

int noop_prepare_write(struct inode *ino, struct page *page, size_t page_off, size_t offset,
                       size_t len)
{
    return 0;
}
