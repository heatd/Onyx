/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/compiler.h>
#include <onyx/dentry.h>
#include <onyx/file.h>
#include <onyx/gen/trace_dentry.h>
#include <onyx/mm/slab.h>
#include <onyx/mtable.h>
#include <onyx/namei.h>
#include <onyx/rculist.h>
#include <onyx/seqlock.h>
#include <onyx/user.h>
#include <onyx/vfs.h>
#include <onyx/wait.h>

#include <onyx/expected.hpp>
#include <onyx/hashtable.hpp>
#include <onyx/list.hpp>
#include <onyx/memory.hpp>
#include <onyx/string_view.hpp>

static struct slab_cache *dentry_cache;

/* rename_lock is held (write!) throughout a *dcache-level* rename. This protects against hashtable
 * entries going bad, and against ->d_parent being changed. It's held in read-mode when traversing
 * the dcache hashtable. */
static seqlock_t rename_lock;

fnv_hash_t hash_dentry(dentry *&d)
{
    auto hash = fnv_hash(&d->d_parent, sizeof(dentry *));
    hash = fnv_hash_cont(d->d_name, d->d_name_length, hash);
    return hash;
}

fnv_hash_t hash_dentry_fields(dentry *parent, std::string_view name)
{
    auto hash = fnv_hash(&parent, sizeof(dentry *));
    hash = fnv_hash_cont(name.data(), name.length(), hash);
    return hash;
}

cul::hashtable2<dentry *, 1024, fnv_hash_t, hash_dentry> dentry_ht;
static spinlock dentry_ht_locks[1024];

[[gnu::always_inline]] static inline bool dentry_compare_name(dentry *dent,
                                                              std::string_view &to_cmp)
{
    std::string_view dent_name{dent->d_name, dent->d_name_length};
    return dent_name.compare(to_cmp) == 0;
}

static inline int d_revalidate(struct dentry *dentry, unsigned int flags)
{
    if (dentry->d_ops->d_revalidate) [[unlikely]]
        return dentry->d_ops->d_revalidate(dentry, flags);
    return 1;
}

void dentry_remove_from_cache(dentry *dent, dentry *parent);

static dentry *d_lookup_internal(dentry *dent, std::string_view name)
{
    auto namehash = fnv_hash(name.data(), name.length());
    auto hash = hash_dentry_fields(dent, name);
    auto index = dentry_ht.get_hashtable_index(hash);
    auto list = dentry_ht.get_hashtable(index);

    list_for_every_rcu (list)
    {
        struct dentry *d = container_of(l, struct dentry, d_cache_node);

        if (d->d_parent != dent || d->d_name_hash != namehash)
            continue;

        spin_lock(&d->d_lock);
        if ((d->d_flags & DENTRY_FLAG_HASHED) == 0)
            goto skip;
        if (d->d_parent == dent && d->d_name_hash == namehash && dentry_compare_name(d, name))
        {
            dget(d);
            spin_unlock(&d->d_lock);
            return d;
        }
    skip:
        spin_unlock(&d->d_lock);
    }

    return nullptr;
}

static dentry *dentry_open_from_cache(dentry *dent, std::string_view name)
{
    unsigned int old;
    struct dentry *found;
    rcu_read_lock();

    do
    {
        old = read_seqbegin(&rename_lock);
        found = d_lookup_internal(dent, name);
        if (found)
            break;
    } while (read_seqretry(&rename_lock, old));

    rcu_read_unlock();

    if (found)
    {
        if (!d_revalidate(found, 0))
        {
            dput(found);
            /* TODO: HACK! This is not safe nor correct! We'll do it this way, temporarily,
             * because of devfs and block device rescanning! */
            dentry_remove_from_cache(found, found->d_parent);
            dput(found);
            return nullptr;
        }
    }

    return found;
}

void dentry_remove_from_cache(dentry *dent, dentry *parent)
{
    auto hash = hash_dentry_fields(parent, std::string_view{dent->d_name, dent->d_name_length});
    auto index = dentry_ht.get_hashtable_index(hash);
    spin_lock(&dentry_ht_locks[index]);

    list_remove_rcu(&dent->d_cache_node);
    dent->d_flags &= ~DENTRY_FLAG_HASHED;
    spin_unlock(&dentry_ht_locks[index]);
}

static void dentry_add_to_cache(dentry *dent, dentry *parent)
{
    auto hash = hash_dentry_fields(parent, std::string_view{dent->d_name, dent->d_name_length});
    auto index = dentry_ht.get_hashtable_index(hash);
    spin_lock(&dentry_ht_locks[index]);

    list_add_tail_rcu(&dent->d_cache_node, dentry_ht.get_hashtable(index));
    dent->d_flags |= DENTRY_FLAG_HASHED;
    spin_unlock(&dentry_ht_locks[index]);
}

static struct dentry *dentry_add_to_cache_careful(dentry *dent, dentry *parent)
{
    /* Lets add to the cache while checking for conflicts. If we find one, we return that dentry */
    const std::string_view name = std::string_view{dent->d_name, dent->d_name_length};
    fnv_hash_t hash = hash_dentry_fields(parent, name);
    size_t index = dentry_ht.get_hashtable_index(hash);
    struct dentry *ret;
    spin_lock(&dentry_ht_locks[index]);

    ret = d_lookup_internal(parent, name);
    if (ret)
    {
        /* We lost the parallel lookup race and found a dentry, lets put the current one and return
         * this one. */
        spin_unlock(&dentry_ht_locks[index]);
        dput(dent);
        return ret;
    }

    list_add_tail_rcu(&dent->d_cache_node, dentry_ht.get_hashtable(index));
    dent->d_flags |= DENTRY_FLAG_HASHED;
    spin_unlock(&dentry_ht_locks[index]);
    return dent;
}

#define READ_ONCE(var) (__atomic_load_n(&(var), __ATOMIC_RELAXED))

static inline void dget_locked(struct dentry *d)
{
    /* We already have a locked dentry, just do an *atomic* add. We cna skip the cmpxchg loop,
     * because refs may only become locked under d_lock, which we already hold. */
    __atomic_add_fetch(&d->d_ref, 1, __ATOMIC_RELAXED);
}

void dget(struct dentry *d)
{
    DCHECK(d != nullptr);
    unsigned long val = READ_ONCE(d->d_ref);
    unsigned long new_val;
    bool success = false;
    int retry = 100;

    trace_dentry_dget((unsigned long) d, READ_ONCE(d->d_ref), READ_ONCE(d->d_name));

    do
    {
        if (unlikely(val & D_REF_LOCKED))
            break;
        if (retry-- == 0)
            break;
        new_val = val + 1;
        WARN_ON(new_val & D_REF_LOCKED);
    } while (!(success = __atomic_compare_exchange_n(&d->d_ref, &val, new_val, false,
                                                     __ATOMIC_RELAXED, __ATOMIC_RELAXED)));
    if (likely(success))
        return;

    spin_lock(&d->d_lock);
    DCHECK(!(READ_ONCE(d->d_ref) & D_REF_LOCKED));
    dget_locked(d);
    spin_unlock(&d->d_lock);
}

/**
 * @brief dput - fast version.
 * Does not grab locks, only tries atomic d_ref manipulation
 *
 * @param d
 * @return New d_ref, or -1 if we failed.
 */
static inline long __dput_fast(struct dentry *d)
{
    unsigned long val = READ_ONCE(d->d_ref), new_val;
    int retry = 100;

    do
    {
        if (unlikely(val & D_REF_LOCKED))
            return -1;
        if (retry-- == 0)
            return -1;

        WARN_ON(val == 0);
        new_val = val - 1;
    } while (!__atomic_compare_exchange_n(&d->d_ref, &val, new_val, false, __ATOMIC_RELAXED,
                                          __ATOMIC_RELAXED));

    return new_val;
}

static inline long dput_locked(struct dentry *dentry)
{
    return __atomic_sub_fetch(&dentry->d_ref, 1, __ATOMIC_RELAXED) & ~D_REF_LOCKED;
}

static inline void d_freeze_refs(struct dentry *dentry)
{
    __atomic_or_fetch(&dentry->d_ref, D_REF_LOCKED, __ATOMIC_ACQUIRE);
}

static inline void d_unfreeze_refs(struct dentry *dentry)
{
    __atomic_and_fetch(&dentry->d_ref, ~D_REF_LOCKED, __ATOMIC_RELEASE);
}

static inline void d_add_lru(struct dentry *dentry)
{
    DCHECK(spin_lock_held(&dentry->d_lock));
    DCHECK(!(dentry->d_flags & (DENTRY_FLAG_LRU | DENTRY_FLAG_SHRINK)));
    struct superblock *sb;
    /* Sniff out the sb from our inode, or our parent's inode. This _should_ be safe, our parent's
     * inode can't go away magically. */

    if (dentry->d_inode)
        sb = dentry->d_inode->i_sb;
    else
        sb = dentry->d_parent->d_inode->i_sb;
    DCHECK(sb != nullptr);

    dentry->d_flags |= DENTRY_FLAG_LRU;
    lru_list_add(&sb->s_dcache_lru, &dentry->d_lru);
}

static inline void d_remove_lru(struct dentry *dentry)
{
    DCHECK((dentry->d_flags & (DENTRY_FLAG_LRU | DENTRY_FLAG_SHRINK)) == DENTRY_FLAG_LRU);
    DCHECK(spin_lock_held(&dentry->d_lock));

    struct superblock *sb;
    /* Sniff out the sb from our inode, or our parent's inode. This _should_ be safe, our parent's
     * inode can't go away magically. */

    if (dentry->d_inode)
        sb = dentry->d_inode->i_sb;
    else
        sb = dentry->d_parent->d_inode->i_sb;

    lru_list_remove(&sb->s_dcache_lru, &dentry->d_lru);
    dentry->d_flags &= ~DENTRY_FLAG_LRU;
}

static bool d_should_retain(struct dentry *dentry, bool locked)
{
    unsigned long flags;
    smp_rmb();

    flags = dentry->d_flags.load(mem_order::relaxed);
    if (!(flags & DENTRY_FLAG_HASHED))
        return false;

    if (!(flags & DENTRY_FLAG_LRU))
    {
        /* If not in an LRU, try to add it (if locked) */
        if (!locked)
            return false;
        d_add_lru(dentry);
    }
    else if (!(flags & DENTRY_FLAG_REFERENCED))
        dentry->d_flags |= DENTRY_FLAG_REFERENCED;

    return true;
}

static inline unsigned long d_refs(struct dentry *dentry)
{
    return READ_ONCE(dentry->d_ref) & ~D_REF_LOCKED;
}

/**
 * @brief Put a dentry
 * We try not to grab the lock, but sometimes it's inevitable.
 *
 * @param dentry dentry
 * @return True if dput_fast worked, false if need to whack the dentry (and we hold the d_lock)
 */
static bool dput_fast(struct dentry *dentry)
{
    long refs = __dput_fast(dentry);

    if (refs < 0)
    {
        spin_lock(&dentry->d_lock);
        if (dput_locked(dentry) > 0)
        {
            spin_unlock(&dentry->d_lock);
            return true;
        }

        goto locked;
    }

    if (refs > 0)
        return true;

    if (d_should_retain(dentry, false))
        return true;

    spin_lock(&dentry->d_lock);

locked:
    d_freeze_refs(dentry);

    if (d_refs(dentry) > 0 || d_should_retain(dentry, true))
    {
        d_unfreeze_refs(dentry);
        spin_unlock(&dentry->d_lock);
        return true;
    }

    return false;
}

static unsigned long d_stroyed = 0;

static struct dentry *d_destroy(struct dentry *dentry)
{
    /* Refs frozen, d_lock held */
    struct dentry *parent;
    DCHECK(READ_ONCE(dentry->d_ref) & D_REF_LOCKED);
    DCHECK(spin_lock_held(&dentry->d_lock));

    d_stroyed++;

    if (dentry->d_flags & DENTRY_FLAG_HASHED)
        dentry_remove_from_cache(dentry, dentry->d_parent);

    if ((dentry->d_flags & (DENTRY_FLAG_LRU | DENTRY_FLAG_SHRINK)) == DENTRY_FLAG_LRU)
        d_remove_lru(dentry);

    if (dentry->d_inode)
    {
        /* Lets take this moment to gather the inode, release the lock and _then_ put the inode */
        struct inode *ino = dentry->d_inode;
        dentry->d_inode = NULL;
        spin_unlock(&dentry->d_lock);
        inode_unref(ino);
    }
    else
        spin_unlock(&dentry->d_lock);

    /* d_parent is stable because we're now *kind of* a negative entry */
    parent = dentry->d_parent;

    if (parent)
    {
        spin_lock(&parent->d_lock);
        /* Freeze refs. We'll see if we want to whack the parent dentry and return it if so */
        d_freeze_refs(parent);
        list_remove(&dentry->d_parent_dir_node);
    }

    if (dentry->d_name_length >= INLINE_NAME_MAX)
        free((void *) dentry->d_name);

    DCHECK(READ_ONCE(dentry->d_ref) == D_REF_LOCKED);
    dentry->~dentry();
    kfree_rcu(dentry, d_rcu);

    if (parent)
    {
        if (dput_locked(parent) == 0 && !d_should_retain(parent, true))
            return parent;
        d_unfreeze_refs(parent);
        spin_unlock(&parent->d_lock);
    }

    return NULL;
}

void dput(struct dentry *d)
{
    DCHECK(d != nullptr);
    MAY_SLEEP();
    if (likely(dput_fast(d)))
        return;
    /* refs frozen, lock held */
    while ((d = d_destroy(d)))
        ;
}

/**
 * @brief Fail a dentry lookup
 *
 * @param d Dentry
 */
void dentry_fail_lookup(struct dentry *d)
{
    dentry_remove_from_cache(d, d->d_parent);

    {
        d->d_flags |= DENTRY_FLAG_FAILED;
        d->d_flags &= ~DENTRY_FLAG_PENDING;
    }

    wake_address((void *) &d->d_flags);
}

/**
 * @brief Complete a dentry lookup
 *
 * @param d Dentry
 */
void dentry_complete_lookup(dentry *d)
{
    d->d_flags &= ~DENTRY_FLAG_PENDING;
    wake_address((void *) &d->d_flags);
}

static const struct dentry_operations default_dops = {};

dentry *dentry_create(const char *name, inode *inode, dentry *parent, u16 flags)
{
    if (parent && !S_ISDIR(parent->d_inode->i_mode))
        return errno = ENOTDIR, nullptr;

    /* TODO: Move a bunch of this code to a constructor and placement-new it */
    dentry *new_dentry = (dentry *) kmem_cache_alloc(dentry_cache, 0);
    if (!new_dentry) [[unlikely]]
        return nullptr;

    new_dentry = new (new_dentry) dentry;

    spinlock_init(&new_dentry->d_lock);
    new_dentry->d_ref = 0;
    new_dentry->d_name = new_dentry->d_inline_name;

    size_t name_length = strlen(name);

    if (name_length < INLINE_NAME_MAX)
    {
        strlcpy(new_dentry->d_name, name, INLINE_NAME_MAX);
    }
    else
    {
        char *dname = (char *) memdup((void *) name, name_length + 1);
        if (!dname)
        {
            kmem_cache_free(dentry_cache, new_dentry);
            return nullptr;
        }

        new_dentry->d_name = dname;
    }

    new_dentry->d_name_length = name_length;
    new_dentry->d_name_hash = fnv_hash(new_dentry->d_name, new_dentry->d_name_length);
    new_dentry->d_inode = inode;

    /* We need this if() because we might call dentry_create before retrieving an inode */
    if (inode)
        inode_ref(inode);
    new_dentry->d_parent = parent;

    if (parent) [[likely]]
    {
        list_add_tail(&new_dentry->d_parent_dir_node, &parent->d_children_head);
        dget(parent);
    }

    INIT_LIST_HEAD(&new_dentry->d_children_head);

    new_dentry->d_ops = &default_dops;
    new_dentry->d_flags.store(flags, mem_order::release);

    return new_dentry;
}

dentry *dentry_wait_for_pending(dentry *dent)
{
    wait_for(
        &dent->d_flags,
        [](void *addr) -> bool {
            const uint16_t flags = *(uint16_t *) addr;
            return !(flags & DENTRY_FLAG_PENDING);
        },
        WAIT_FOR_FOREVER, 0);

    if (dent->d_flags & DENTRY_FLAG_FAILED)
    {
        dput(dent);
        return nullptr;
    }

    return dent;
}

static expected<dentry *, int> dentry_create_pending_lookup(const char *name, inode *ino,
                                                            dentry *parent)
{
    struct dentry *dent = dentry_open_from_cache(parent, std::string_view(name));
    if (dent)
    {
        dent = dentry_wait_for_pending(dent);
        if (dent)
            return dent;
    }

    /* Dentry not found, lets create a lookup. We must be careful as to avoid duplicate dentries */
    dent = dentry_create(name, ino, parent, DENTRY_FLAG_PENDING);
    if (!dent)
        return unexpected<int>{-ENOMEM};
    dent->d_ref = 1;

    return dentry_add_to_cache_careful(dent, parent);
}

static dentry *__dentry_try_to_open(std::string_view name, dentry *dir, bool lock_ino)
{
    DCHECK(dentry_is_dir(dir));
    if (auto d = dentry_open_from_cache(dir, name); d)
    {
        if (d->d_flags & DENTRY_FLAG_PENDING)
            d = dentry_wait_for_pending(d);
        return d;
    }

    // printk("trying to open %.*s in %s\n", (int) name.length(), name.data(), dir->d_name);
    char _name[NAME_MAX + 1] = {};
    memcpy(_name, name.data(), name.length());
    auto ex = dentry_create_pending_lookup(_name, nullptr, dir);

    if (ex.has_error())
        return errno = -ex.error(), nullptr;

    auto dent = ex.value();

    if (!(dent->d_flags & DENTRY_FLAG_PENDING))
    {
        // We got lucky and got someone else's resolution.
        // Easy.
        return dent;
    }

    // For in memory filesystems like tmpfs where everything is in the dcache
    if (dir->d_inode->i_sb->s_flags & SB_FLAG_IN_MEMORY)
    {
        d_complete_negative(dent);
        return dent;
    }

    auto pino = dir->d_inode;

    // Note: We only lock the inode if the caller hasn't locked it yet
    // This is useful for e.g otomic O_CREAT handling
    if (lock_ino)
        inode_lock_shared(pino);

    int st = dir->d_inode->i_fops->open(dir, _name, dent);

    if (lock_ino)
        inode_unlock_shared(pino);

    if (st < 0)
    {
        /* If this was an ENOENT, complete it as normal */
        if (st == -ENOENT)
        {
            d_complete_negative(dent);
            return dent;
        }

        dentry_fail_lookup(dent);
        dput(dent);
        return nullptr;
    }

    DCHECK(!(dent->d_flags & DENTRY_FLAG_PENDING));

    return dent;
}

struct dentry *__dentry_parent(struct dentry *dir)
{
    auto ret = dir->d_parent;

    if (ret)
        dget(ret);

    return ret;
}

struct dentry *dentry_parent(struct dentry *dir)
{
    spin_lock(&dir->d_lock);
    struct dentry *parent = __dentry_parent(dir);
    spin_unlock(&dir->d_lock);
    return parent;
}

dentry *dentry_lookup_internal(std::string_view v, dentry *dir, dentry_lookup_flags_t flags)
{
    if (!dentry_is_dir(dir))
        return errno = ENOTDIR, nullptr;

    if (!v.compare("."))
    {
        dget(dir);
        return dir;
    }

    if (!v.compare(".."))
    {
        auto dent = dentry_parent(dir);
        if (!dent)
        {
            dent = dir;
            dget(dent);
        }

        return dent;
    }

    dentry *dent = dentry_open_from_cache(dir, v);

    if (dent)
    {
        if (dent->d_flags & DENTRY_FLAG_PENDING)
            dent = dentry_wait_for_pending(dent);
    }

    if (!dent)
        dent = __dentry_try_to_open(v, dir, !(flags & DENTRY_LOOKUP_UNLOCKED));
    return dent;
}

void dentry_init()
{
    dentry_cache = kmem_cache_create("dentry", sizeof(dentry), 0, KMEM_CACHE_HWALIGN, nullptr);
    CHECK(dentry_cache != nullptr);
}

struct path_element
{
    dentry *d;
    struct list_head node;
};

char *dentry_to_file_name(struct dentry *dentry)
{
    /* Calculate the initial length as / + the null terminator */
    size_t buf_len = 2;
    char *buf = nullptr;
    char *s = nullptr;
    struct path p = get_filesystem_root();
    auto fs_root = p.dentry;

    if (fs_root == dentry)
    {
        path_put(&p);
        return strdup("/");
    }

    dget(fs_root);
    path_put(&p);

    auto d = dentry;
    struct list_head element_list;
    INIT_LIST_HEAD(&element_list);

    /* Get another ref here to have prettier code */
    dget(d);

    /* TODO: Is this logic safe from race conditions? */
    while (d != fs_root && d != nullptr)
    {
        path_element *p = new path_element;
        if (!p)
            goto error;
        p->d = d;
        /* Add 1 to the len because of the separator */
        buf_len += d->d_name_length + 1;
        list_add(&p->node, &element_list);

        if (d->d_flags & DENTRY_FLAG_MOUNT_ROOT)
        {
            // HACK!
            d = dentry_parent(d);
            while (d && d->d_flags & DENTRY_FLAG_MOUNTPOINT)
                d = dentry_parent(d);
        }
        else
            d = dentry_parent(d);
    }

    /* Remove one from the end to avoid trailing slashes */
    buf_len--;

    buf = (char *) malloc(buf_len);
    if (!buf)
        goto error;
    buf[0] = '/';
    s = &buf[1];

    list_for_every_safe (&element_list)
    {
        auto elem = container_of(l, struct path_element, node);
        auto dent = elem->d;
        memcpy(s, dent->d_name, dent->d_name_length);
        s += dent->d_name_length;
        *s++ = '/';
        dput(dent);
        delete elem;
    }

    buf[buf_len - 1] = '\0';
    dput(fs_root);
    return buf;

error:
    dput(fs_root);
    list_for_every_safe (&element_list)
    {
        auto elem = container_of(l, struct path_element, node);
        dput(elem->d);
        delete elem;
    }

    return nullptr;
}

void dentry_shrink_subtree(struct dentry *dentry);

void dentry_do_unlink(dentry *entry)
{
    /* Perform the actual unlink, by write-locking, nulling d_parent */
    spin_lock(&entry->d_lock);

    auto parent = entry->d_parent;
    DCHECK(spin_lock_held(&parent->d_lock));
    dput_locked(parent);
    entry->d_parent = nullptr;

    if (!d_is_negative(entry))
    {
        inode_dec_nlink(entry->d_inode);

        if (dentry_is_dir(entry))
        {
            inode_dec_nlink(parent->d_inode);
            inode_dec_nlink(entry->d_inode);
            dentry_shrink_subtree(entry);
        }
    }

    dentry_remove_from_cache(entry, parent);
    spin_unlock(&entry->d_lock);

    // We can do this because we're holding the parent dir's lock
    list_remove(&entry->d_parent_dir_node);
}

bool dentry_does_not_have_parent(dentry *dir, dentry *to_not_have)
{
    struct path root = get_filesystem_root();
    auto_dentry fs_root = root.dentry;
    auto_dentry d = dir;

    /* Get another ref here to have prettier code */
    dget(d.get_dentry());
    dget(fs_root.get_dentry());
    path_put(&root);

    /* TODO: Is this logic safe from race conditions? */
    while (d.get_dentry() != fs_root.get_dentry() && d.get_dentry() != nullptr)
    {
        if (d.get_dentry() == to_not_have)
            return false;

        d = __dentry_parent(d.get_dentry());
    }

    return true;
}

void dentry_move(dentry *target, dentry *new_parent)
{
    list_remove(&target->d_parent_dir_node);

    list_add_tail(&target->d_parent_dir_node, &new_parent->d_children_head);

    auto old = target->d_parent;
    target->d_parent = new_parent;

    if (dentry_is_dir(target))
        inode_dec_nlink(old->d_inode);

    dget(old);
}

static bool dentry_is_in_chain(struct dentry *dentry, unsigned long chain)
{
    struct list_head *list = dentry_ht.get_hashtable(chain);
    list_for_every (list)
    {
        struct dentry *dent = container_of(l, struct dentry, d_cache_node);
        if (dent == dentry)
            return true;
    }

    return false;
}

void dentry_do_rename_unlink(dentry *entry)
{
    /* Perform the actual unlink, by write-locking, nulling d_parent */
    spin_lock(&entry->d_lock);

    auto parent = entry->d_parent;
    DCHECK(spin_lock_held(&parent->d_lock));
    WARN_ON(dput_locked(parent) == 0);
    entry->d_parent = nullptr;

    /* The dcache buckets are already locked, so we don't grab the lock again. Just open-code the
     * removal. */
    list_remove_rcu(&entry->d_cache_node);
    entry->d_flags &= ~DENTRY_FLAG_HASHED;

    if (!d_is_negative(entry) && dentry_is_dir(entry))
        dentry_shrink_subtree(entry);

    spin_unlock(&entry->d_lock);

    // We can do this because we're holding the parent dir's lock
    list_remove(&entry->d_parent_dir_node);
}

void dentry_rename(dentry *dent, const char *name, dentry *parent,
                   dentry *dst) NO_THREAD_SAFETY_ANALYSIS
{
    size_t name_length = strlen(name);
    char *newname = nullptr;
    struct dentry *old = nullptr;
    fnv_hash_t old_hash =
        hash_dentry_fields(dent->d_parent, std::string_view{dent->d_name, dent->d_name_length});
    fnv_hash_t new_hash = hash_dentry_fields(parent, std::string_view{name, name_length});
    unsigned long oldi = dentry_ht.get_hashtable_index(old_hash);
    unsigned long newi = dentry_ht.get_hashtable_index(new_hash);

    write_seqlock(&rename_lock);

    /* General strategy: We need the rename to be atomic. We'll do the name exchange under the
     * lock. We must be careful wrt lock ordering. */
    if (name_length >= INLINE_NAME_MAX)
    {
        newname = (char *) memdup(name, name_length + 1);
        CHECK(newname != nullptr);
    }

    /* Lock the two dcache chains. Smaller first. */
    if (oldi < newi)
    {
        spin_lock(&dentry_ht_locks[oldi]);
        spin_lock(&dentry_ht_locks[newi]);
    }
    else if (oldi > newi)
    {
        spin_lock(&dentry_ht_locks[newi]);
        spin_lock(&dentry_ht_locks[oldi]);
    }
    else
    {
        /* We're working with a single hash chain */
        spin_lock(&dentry_ht_locks[oldi]);
    }

    dentry_do_rename_unlink(dst);
    spin_lock(&dent->d_lock);

    DCHECK(dentry_is_in_chain(dent, oldi));

    list_remove_rcu(&dent->d_cache_node);
    list_add_tail_rcu(&dent->d_cache_node, dentry_ht.get_hashtable(newi));

    if (parent != dent->d_parent)
    {
        /* Re-parent the dentry */
        old = dent->d_parent;

        if (old < parent)
        {
            spin_lock(&old->d_lock);
            spin_lock(&parent->d_lock);
        }
        else
        {
            spin_lock(&parent->d_lock);
            spin_lock(&old->d_lock);
        }

        list_remove(&dent->d_parent_dir_node);
        list_add_tail(&dent->d_parent_dir_node, &parent->d_children_head);
        dent->d_parent = parent;
        dget_locked(parent);

        if (old < parent)
        {
            spin_unlock(&parent->d_lock);
            spin_unlock(&old->d_lock);
        }
        else
        {
            spin_unlock(&old->d_lock);
            spin_unlock(&parent->d_lock);
        }
    }

    /* Replace the name... */
    if (name_length < INLINE_NAME_MAX)
    {
        strlcpy(dent->d_inline_name, name, INLINE_NAME_MAX);

        /* It's in this exact order so we don't accidentally touch free'd memory or
         * an invalid d_name that resulted from a non-filled inline d_name.
         */
        if (dent->d_name != dent->d_inline_name)
        {
            auto old = dent->d_name;
            dent->d_name = dent->d_inline_name;
            free(old);
        }
    }
    else
    {
        auto old = dent->d_name;
        dent->d_name = newname;
        if (old != dent->d_inline_name)
            free(old);
    }

    dent->d_name_length = name_length;
    dent->d_name_hash = fnv_hash(name, name_length);
    spin_unlock(&dent->d_lock);

    if (oldi < newi)
    {
        spin_unlock(&dentry_ht_locks[newi]);
        spin_unlock(&dentry_ht_locks[oldi]);
    }
    else if (oldi > newi)
    {
        spin_unlock(&dentry_ht_locks[oldi]);
        spin_unlock(&dentry_ht_locks[newi]);
    }
    else
        spin_unlock(&dentry_ht_locks[oldi]);

    write_sequnlock(&rename_lock);

    if (old)
        dput(old);
}

bool dentry_is_empty(dentry *dir)
{
    bool empty = true;
    spin_lock(&dir->d_lock);
    list_for_every_safe (&dir->d_children_head)
    {
        struct dentry *dentry = container_of(l, struct dentry, d_parent_dir_node);
        if (!d_is_negative(dentry))
        {
            empty = false;
            break;
        }
    }

    spin_unlock(&dir->d_lock);
    return empty;
}

/**
 * @brief Trim the dentry caches
 *
 */
void dentry_trim_caches()
{
    kmem_cache_purge(dentry_cache);
}

/**
 * @brief Finish a VFS lookup
 *
 * @param dentry Dentry to finish
 * @param inode Lookup's result
 */
void d_finish_lookup(struct dentry *dentry, struct inode *inode)
{
    DCHECK(inode != nullptr);
    dentry->d_inode = inode;
    if (dentry_is_dir(dentry))
        inode->i_dentry = dentry;

    dentry_complete_lookup(dentry);
}

void d_complete_negative(struct dentry *dentry)
{
    dentry->d_flags.or_fetch(DENTRY_FLAG_NEGATIVE, mem_order::release);
    dentry_complete_lookup(dentry);
}

void d_positiveize(struct dentry *dentry, struct inode *inode)
{
    DCHECK(inode != nullptr);
    DCHECK(dentry->d_inode == nullptr);
    DCHECK(dentry->d_flags & DENTRY_FLAG_NEGATIVE);
    dentry->d_inode = inode;
    dentry->d_flags.and_fetch(~DENTRY_FLAG_NEGATIVE, mem_order::release);
}

enum d_walk_ret
{
    D_WALK_CONTINUE,
    D_WALK_QUIT,
    D_WALK_NORETRY,
    D_WALK_SKIP,
    __D_WALK_RESTART
};

struct d_walk_state
{
    struct dentry *root;
    struct dentry *parent;
    struct dentry *dentry;
    unsigned int seq;
    enum d_walk_ret stop;
    bool retry;
};

static void d_ascend(struct d_walk_state *state)
{
    struct dentry *parent = state->parent;
    struct dentry *parent2 = parent->d_parent;

    if (state->root == parent)
    {
        state->stop = D_WALK_QUIT;
        return;
    }

    rcu_read_lock();
    spin_unlock(&parent->d_lock);
    spin_lock(&parent2->d_lock);
    /* Let's be careful going up... If we had a rename at the same time, restart the whole
     * process *with rename_lock held* */
    if (read_seqretry(&rename_lock, state->seq))
    {
        spin_unlock(&parent2->d_lock);
        state->seq = 1;
        if (state->retry)
        {
            read_seqbegin_or_lock(&rename_lock, &state->seq);
            state->stop = __D_WALK_RESTART;
        }
        else
            state->stop = D_WALK_QUIT;
        rcu_read_unlock();
        return;
    }

    state->parent = parent2;
    state->dentry = parent;
    rcu_read_unlock();
}

void d_walk(struct dentry *parent, void *data,
            enum d_walk_ret (*enter)(void *data, struct dentry *))
{
    struct d_walk_state state;
    enum d_walk_ret ret;
    state.seq = 0;
    state.retry = true;
    read_seqbegin_or_lock(&rename_lock, &state.seq);
restart:
    state.root = parent;
    state.parent = parent;
    state.dentry = NULL;
    state.stop = D_WALK_CONTINUE;
    spin_lock(&state.parent->d_lock);

    ret = enter(data, state.parent);
    switch (ret)
    {
        case D_WALK_CONTINUE:
            break;
        case D_WALK_NORETRY:
            state.retry = false;
            break;
        case D_WALK_SKIP:
        case D_WALK_QUIT:
            goto out;
        case __D_WALK_RESTART:
            spin_unlock(&state.parent->d_lock);
            goto restart;
    }

    while (state.stop != D_WALK_QUIT)
    {
    repeat:
        state.dentry =
            list_prepare_entry(state.dentry, &state.parent->d_children_head, d_parent_dir_node);

        list_for_each_entry_continue(state.dentry, &state.parent->d_children_head,
                                     d_parent_dir_node)
        {
            spin_lock(&state.dentry->d_lock);
            ret = enter(data, state.dentry);
            switch (ret)
            {
                case D_WALK_CONTINUE:
                    break;
                case D_WALK_NORETRY:
                    state.retry = false;
                    break;
                case D_WALK_SKIP:
                    spin_unlock(&state.dentry->d_lock);
                    continue;
                case D_WALK_QUIT:
                    spin_unlock(&state.dentry->d_lock);
                    goto out;
                case __D_WALK_RESTART:
                    spin_unlock(&state.dentry->d_lock);
                    goto restart;
            }

            if (!list_is_empty(&state.dentry->d_children_head))
            {
                spin_unlock(&state.parent->d_lock);
                state.parent = state.dentry;
                state.dentry = NULL;
                goto repeat;
            }

            spin_unlock(&state.dentry->d_lock);
        }

        d_ascend(&state);
        if (state.stop == __D_WALK_RESTART)
            goto restart;
    }

out:
    spin_unlock(&state.parent->d_lock);
    done_seqretry(&rename_lock, state.seq);
}

struct shrink_data
{
    struct list_head shrink_list;
};

static d_walk_ret find_shrink(void *data, struct dentry *dentry)
{
    struct shrink_data *s = (struct shrink_data *) data;
    if (dentry->d_ref == 0)
    {
        if (!(dentry->d_flags & DENTRY_FLAG_SHRINK))
        {
            if (dentry->d_flags & DENTRY_FLAG_LRU)
                d_remove_lru(dentry);

            list_add_tail(&dentry->d_lru, &s->shrink_list);
            dentry->d_flags |= DENTRY_FLAG_SHRINK | DENTRY_FLAG_LRU;
        }
    }

    return D_WALK_CONTINUE;
}

static void kill_one(struct dentry *dentry)
{
    spin_lock(&dentry->d_lock);
    d_freeze_refs(dentry);

    if (d_refs(dentry) != 0)
    {
        d_unfreeze_refs(dentry);
        spin_unlock(&dentry->d_lock);
        return;
    }

    while ((dentry = d_destroy(dentry)))
        ;
}

void shrink_list(struct shrink_data *s)
{
    list_for_every_safe (&s->shrink_list)
    {
        struct dentry *dentry = container_of(l, struct dentry, d_lru);
        list_remove(&dentry->d_lru);
        kill_one(dentry);
    }
}

void dentry_shrink_subtree(struct dentry *dentry)
{
    struct shrink_data data;
    INIT_LIST_HEAD(&data.shrink_list);
    for (;;)
    {
        d_walk(dentry, &data, find_shrink);
        if (list_is_empty(&data.shrink_list))
            break;
        shrink_list(&data);
    }
}

enum lru_walk_ret scan_dcache_lru_one(struct lru_list *lru, struct list_head *object, void *data)
{
    struct dentry *dentry = container_of(object, struct dentry, d_lru);
    struct dcache_scan_result *scan_res = (struct dcache_scan_result *) data;
    if (spin_try_lock(&dentry->d_lock))
        return LRU_WALK_SKIP;
    d_freeze_refs(dentry);

    if (d_refs(dentry) == 0)
    {
        scan_res->scanned_bytes += sizeof(struct dentry) + dentry->d_name_length;
        scan_res->scanned_objs++;
    }

    d_unfreeze_refs(dentry);
    spin_unlock(&dentry->d_lock);
    return LRU_WALK_SKIP;
}

enum lru_walk_ret shrink_dcache_lru_one(struct lru_list *lru, struct list_head *object, void *data)
{
    struct dentry *dentry = container_of(object, struct dentry, d_lru);
    struct dcache_shrink_result *shrink_res = (struct dcache_shrink_result *) data;
    if (!shrink_res->to_shrink_objs)
        return LRU_WALK_STOP;

    if (spin_try_lock(&dentry->d_lock))
        return LRU_WALK_SKIP;

    if (dentry->d_flags & DENTRY_FLAG_REFERENCED)
    {
        dentry->d_flags &= ~DENTRY_FLAG_REFERENCED;
        spin_unlock(&dentry->d_lock);
        return LRU_WALK_ROTATE;
    }

    /* No need to freeze refs, shrink_list will take care of the final check */
    if (d_refs(dentry) > 0)
    {
        spin_unlock(&dentry->d_lock);
        return LRU_WALK_SKIP;
    }

    dentry->d_flags |= DENTRY_FLAG_SHRINK;
    list_remove(&dentry->d_lru);
    list_add_tail(&dentry->d_lru, &shrink_res->reclaim_list);
    spin_unlock(&dentry->d_lock);
    shrink_res->to_shrink_objs--;
    return LRU_WALK_REMOVED;
}
