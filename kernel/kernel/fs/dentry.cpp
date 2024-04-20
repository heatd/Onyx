/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
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
#include <onyx/user.h>
#include <onyx/vfs.h>
#include <onyx/wait.h>

#include <onyx/expected.hpp>
#include <onyx/hashtable.hpp>
#include <onyx/list.hpp>
#include <onyx/memory.hpp>
#include <onyx/string_view.hpp>

static struct slab_cache *dentry_cache;
dentry *root_dentry = nullptr;

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
static rwslock dentry_ht_locks[1024];

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

static dentry *dentry_open_from_cache_unlocked(dentry *dent, std::string_view name)
{
    auto namehash = fnv_hash(name.data(), name.length());
    auto hash = hash_dentry_fields(dent, name);
    auto index = dentry_ht.get_hashtable_index(hash);
    auto list = dentry_ht.get_hashtable(index);

    list_for_every (list)
    {
        dentry *d = container_of(l, dentry, d_cache_node);

        if (d->d_parent != dent || d->d_name_hash != namehash)
            continue;

        scoped_rwslock<rw_lock::read> g{d->d_lock};
        if (d->d_parent == dent && d->d_name_hash == namehash && dentry_compare_name(d, name))
        {
            dentry_get(d);

            return d;
        }
    }

    return nullptr;
}

static dentry *dentry_open_from_cache(dentry *dent, std::string_view name)
{
    auto hash = hash_dentry_fields(dent, name);
    auto index = dentry_ht.get_hashtable_index(hash);
    scoped_rwslock<rw_lock::read> g{dentry_ht_locks[index]};

    return dentry_open_from_cache_unlocked(dent, name);
}

void dentry_remove_from_cache(dentry *dent, dentry *parent)
{
    auto hash = hash_dentry_fields(parent, std::string_view{dent->d_name, dent->d_name_length});
    auto index = dentry_ht.get_hashtable_index(hash);
    scoped_rwslock<rw_lock::write> g{dentry_ht_locks[index]};

    list_remove(&dent->d_cache_node);
}

static void dentry_add_to_cache(dentry *dent, dentry *parent)
{
    auto hash = hash_dentry_fields(parent, std::string_view{dent->d_name, dent->d_name_length});
    auto index = dentry_ht.get_hashtable_index(hash);
    scoped_rwslock<rw_lock::write> g{dentry_ht_locks[index]};

    list_add_tail(&dent->d_cache_node, dentry_ht.get_hashtable(index));
}

void dentry_get(dentry *d)
{
    DCHECK(d != nullptr);
    /* Must hold parent's d_lock */
    __atomic_add_fetch(&d->d_ref, 1, __ATOMIC_ACQUIRE);
    trace_dentry_dget((unsigned long) d, d->d_ref, d->d_name);
}

void dentry_put(dentry *d)
{
    DCHECK(d != nullptr);
    trace_dentry_dput((unsigned long) d, d->d_ref - 1, d->d_name);
    if (__atomic_sub_fetch(&d->d_ref, 1, __ATOMIC_RELEASE) == 0)
        dentry_destroy(d);
}

void dentry_destroy(dentry *d)
{
    if (d->d_parent)
    {
        {
            scoped_rwslock<rw_lock::write> g{d->d_parent->d_lock};
            list_remove(&d->d_parent_dir_node);
        }

        dentry_remove_from_cache(d, d->d_parent);

        dentry_put(d->d_parent);
    }

    if (d->d_inode)
        inode_unref(d->d_inode);

    // printk("Dentry %s dead\n", d->d_name);

    if (d->d_name_length > INLINE_NAME_MAX)
    {
        free((void *) d->d_name);
    }

    d->~dentry();
    kmem_cache_free(dentry_cache, d);
}

/**
 * @brief Fail a dentry lookup
 *
 * @param d Dentry
 */
void dentry_fail_lookup(dentry *d)
{
    dentry_remove_from_cache(d, d->d_parent);

    {
        scoped_rwslock<rw_lock::write> g{d->d_parent->d_lock};
        list_remove(&d->d_parent_dir_node);
        dentry_put(d->d_parent);
        d->d_parent = nullptr;
        d->d_flags |= DENTRY_FLAG_FAILED;
        d->d_flags &= ~DENTRY_FLAG_PENDING;
    }

    wake_address((void *) &d->d_flags);
    dentry_put(d);
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

void dentry_kill_unlocked(dentry *entry)
{
    assert(entry->d_ref == 1);

    if (entry->d_parent)
    {
        list_remove(&entry->d_parent_dir_node);
        dentry_put(entry->d_parent);
        entry->d_parent = nullptr;
    }

    dentry_remove_from_cache(entry, entry->d_parent);

    dentry_destroy(entry);
}

static const struct dentry_operations default_dops = {};

dentry *dentry_create(const char *name, inode *inode, dentry *parent)
{
    if (parent && !S_ISDIR(parent->d_inode->i_mode))
        return errno = ENOTDIR, nullptr;

    /* TODO: Move a bunch of this code to a constructor and placement-new it */
    dentry *new_dentry = (dentry *) kmem_cache_alloc(dentry_cache, 0);
    if (!new_dentry) [[unlikely]]
        return nullptr;

    new_dentry = new (new_dentry) dentry;

    new_dentry->d_ref = 1;
    new_dentry->d_name = new_dentry->d_inline_name;

    size_t name_length = strlen(name);

    if (name_length <= INLINE_NAME_MAX)
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
        dentry_get(parent);
    }

    INIT_LIST_HEAD(&new_dentry->d_children_head);

    new_dentry->d_mount_dentry = nullptr;
    new_dentry->d_flags = 0;
    new_dentry->d_ops = &default_dops;

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
        dentry_put(dent);
        return nullptr;
    }

    return dent;
}

static expected<dentry *, int> dentry_create_pending_lookup(const char *name, inode *ino,
                                                            dentry *parent)
{
    auto hash = hash_dentry_fields(parent, name);
    auto index = dentry_ht.get_hashtable_index(hash);
    scoped_rwslock<rw_lock::write> g2{parent->d_lock};
    scoped_rwslock<rw_lock::write> g{dentry_ht_locks[index]};
    auto list = dentry_ht.get_hashtable(index);

    auto dent = dentry_open_from_cache_unlocked(parent, std::string_view(name));

    if (dent)
    {
        g.unlock();
        g2.unlock();
        dent = dentry_wait_for_pending(dent);

        if (dent)
            return dent;
    }

    auto d = dentry_create(name, ino, parent);
    if (!d)
        return unexpected<int>{-ENOMEM};

    d->d_flags |= DENTRY_FLAG_PENDING;

    list_add_tail(&d->d_cache_node, list);
    dentry_get(d);
    return d;
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

        dentry_put(dent);
        dentry_fail_lookup(dent);
        return nullptr;
    }

    DCHECK(!(dent->d_flags & DENTRY_FLAG_PENDING));

    return dent;
}

dentry *__dentry_parent(dentry *dir)
{
    auto ret = dir->d_parent;

    if (ret)
        dentry_get(ret);

    return ret;
}

dentry *dentry_parent(dentry *dir)
{
    scoped_rwslock<rw_lock::read> g{dir->d_lock};

    return __dentry_parent(dir);
}

dentry *dentry_lookup_internal(std::string_view v, dentry *dir, dentry_lookup_flags_t flags)
{
    if (!dentry_is_dir(dir))
        return errno = ENOTDIR, nullptr;

    if (!v.compare("."))
    {
        dentry_get(dir);
        return dir;
    }

    if (!v.compare(".."))
    {
        auto dent = dentry_parent(dir);
        if (!dent)
            dent = dir;
        dentry_get(dent);
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

dentry *dentry_mount(const char *mountpoint, struct inode *inode)
{
    if (!strcmp(mountpoint, "/")) [[unlikely]]
    {
        /* shortpath: We're creating the absolute root inode */
        auto d = (root_dentry = dentry_create(mountpoint, inode, nullptr));
        if (d)
            d->d_flags |= DENTRY_FLAG_MOUNT_ROOT;
        return d;
    }

    char *path = strdup(mountpoint);
    if (!path)
        return nullptr;

    auto fs_root = get_filesystem_root();
    dentry_get(fs_root->file->f_dentry);
    std::string_view name{mountpoint, strlen(mountpoint)};
    nameidata namedata{name, fs_root->file->f_dentry, nullptr};

    auto base_dentry = dentry_resolve(namedata);
    if (!base_dentry)
    {
        free((void *) path);
        return nullptr;
    }

    if (!dentry_is_dir(base_dentry))
    {
        free((void *) path);
        dentry_put(base_dentry);
        errno = ENOTDIR;
        return nullptr;
    }

    dentry *new_d = inode->i_dentry ?: dentry_create(basename(path), inode, base_dentry);

    if (inode->i_dentry)
    {
        /* TODO: I don't believe it's adjusting d_parent properly */
        dentry_put(inode->i_dentry->d_parent);
        dentry_get(base_dentry);
        inode->i_dentry->d_parent = base_dentry;
    }

    if (new_d)
    {
        base_dentry->d_lock.lock_write();
        if (base_dentry->d_flags & DENTRY_FLAG_MOUNTPOINT)
        {
            free((void *) path);
            base_dentry->d_lock.unlock_write();
            return errno = EBUSY, nullptr;
        }

        base_dentry->d_mount_dentry = new_d;
        base_dentry->d_flags |= DENTRY_FLAG_MOUNTPOINT;
        dentry_get(new_d);
        new_d->d_flags |= DENTRY_FLAG_MOUNT_ROOT;
        inode->i_dentry = new_d;

        base_dentry->d_lock.unlock_write();
    }

    free((void *) path);
    dentry_put(base_dentry);

    return new_d;
}

int mount_fs(struct inode *fsroot, const char *path)
{
    assert(fsroot != nullptr);

    printf("mount_fs: Mounting on %s\n", path);

    if (!strcmp(path, "/"))
    {
        file *f = (file *) zalloc(sizeof(*f));
        if (!f)
            return -ENOMEM;
        f->f_ino = fsroot;
        f->f_refcount = 1;
        f->f_dentry = dentry_mount("/", fsroot);
        assert(f->f_dentry != nullptr);

        auto fs_root = get_filesystem_root();
        if (fs_root->file)
        {
            fd_put(fs_root->file);
        }

        fs_root->file = f;
    }
    else
    {
        dentry *d;
        if (!(d = dentry_mount(path, fsroot)))
            return -errno;
        dentry_put(d);
    }

    return 0;
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
    auto fs_root = get_filesystem_root()->file->f_dentry;

    if (fs_root == dentry)
        return strdup("/");

    dentry_get(fs_root);

    auto d = dentry;
    struct list_head element_list;
    INIT_LIST_HEAD(&element_list);

    /* Get another ref here to have prettier code */
    dentry_get(d);

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
            d = dentry_parent(d);
            if (d)
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
        dentry_put(dent);
        delete elem;
    }

    buf[buf_len - 1] = '\0';

    return buf;

error:
    list_for_every_safe (&element_list)
    {
        auto elem = container_of(l, struct path_element, node);
        dentry_put(elem->d);
        delete elem;
    }

    return nullptr;
}

void dentry_do_unlink(dentry *entry)
{
    /* Perform the actual unlink, by write-locking, nulling d_parent */
    entry->d_lock.lock_write();

    auto parent = entry->d_parent;
    dentry_put(parent);
    entry->d_parent = nullptr;

    if (!d_is_negative(entry))
    {
        inode_dec_nlink(entry->d_inode);

        if (dentry_is_dir(entry))
        {
            inode_dec_nlink(parent->d_inode);
            inode_dec_nlink(entry->d_inode);
        }
    }

    dentry_remove_from_cache(entry, parent);

    entry->d_lock.unlock_write();

    // We can do this because we're holding the parent dir's lock
    list_remove(&entry->d_parent_dir_node);

    /* Lastly, release the references */
    dentry_put(entry);
}

bool dentry_does_not_have_parent(dentry *dir, dentry *to_not_have)
{
    auto_dentry fs_root = get_filesystem_root()->file->f_dentry;

    auto_dentry d = dir;

    /* Get another ref here to have prettier code */
    dentry_get(d.get_dentry());

    /* TODO: Is this logic safe from race conditions? */
    while (d.get_dentry() != fs_root.get_dentry() && d.get_dentry() != nullptr)
    {
        if (d.get_dentry() == to_not_have)
        {
            return false;
        }

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

    dentry_get(old);
}

void dentry_rename(dentry *dent, const char *name)
{
    size_t name_length = strlen(name);

    if (name_length <= INLINE_NAME_MAX)
    {
        strlcpy(dent->d_name, name, INLINE_NAME_MAX);

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
        char *dname = (char *) memdup(name, name_length + 1);
        /* TODO: Ugh, how do I handle this? */
        assert(dname != nullptr);

        auto old = dent->d_name;

        dent->d_name = dname;

        if (old != dent->d_inline_name)
        {
            free(old);
        }
    }

    dent->d_name_length = name_length;
    dent->d_name_hash = fnv_hash(dent->d_name, dent->d_name_length);

    dentry_remove_from_cache(dent, dent->d_parent);
    dentry_add_to_cache(dent, dent->d_parent);
}

bool dentry_is_empty(dentry *dir)
{
    scoped_rwslock<rw_lock::write> g{dir->d_lock};
    return list_is_empty(&dir->d_children_head);
}

cul::atomic_size_t killed_dentries = 0;

/**
 * @brief Trim the dentry caches
 *
 */
void dentry_trim_caches()
{
    auto currdent = root_dentry;
    dentry_get(currdent);
    linked_list<dentry *> dentry_queue;

    // For every dentry, try to evict unused children
    while (currdent)
    {

        // If ref > 1, we *may* have children
        if (currdent->d_ref > 1)
        {
            scoped_rwslock<rw_lock::write> g{currdent->d_lock};

            list_for_every_safe (&currdent->d_children_head)
            {
                dentry *d = container_of(l, dentry, d_parent_dir_node);

                if (d->d_ref == 1)
                {
                    // If we're destroying this dentry, take a peek at the parent and
                    // check if they have a ref of 2 (refe'd by themselves for existing, and us)
                    // If so, add their parent to the queue so we can revisit this later.
                    if (d->d_parent && d->d_parent->d_ref == 2)
                    {
                        auto parent = dentry_parent(d->d_parent);
                        dentry_queue.add(parent);
                    }

                    killed_dentries++;
                    // Ready for destruction, remove and destroy
                    dentry_kill_unlocked(d);
                }
                else
                {
                    // Still has refs. If directory, try and clean it up next
                    if (dentry_is_dir(d))
                    {
                        // We need to ref dentries, so we don't lose them magically
                        dentry_get(d);
                        dentry_queue.add(d);
                    }
                }
            }
        }

        dentry_put(currdent);

        currdent = dentry_queue.is_empty() ? nullptr : dentry_queue.pop_head();
    }

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
