/*
 * Copyright (c) 2018 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_DENTRY_H
#define _ONYX_DENTRY_H

#include <stddef.h>
#include <stdint.h>

#include <onyx/fnv.h>
#include <onyx/inode.h>
#include <onyx/limits.h>
#include <onyx/list.h>
#include <onyx/lru.h>
#include <onyx/rcupdate.h>
#include <onyx/rwlock.h>
#include <onyx/seqlock_types.h>

#ifdef __cplusplus
#include <onyx/atomic.hpp>
#endif

struct path;

__BEGIN_CDECLS
#define INLINE_NAME_MAX 40

#define DENTRY_FLAG_MOUNTPOINT (1 << 0)
#define DENTRY_FLAG_MOUNT_ROOT (1 << 1)
#define DENTRY_FLAG_PENDING    (1 << 2)
#define DENTRY_FLAG_FAILED     (1 << 3)
#define DENTRY_FLAG_NEGATIVE   (1 << 4)
#define DENTRY_FLAG_HASHED     (1 << 5)
#define DENTRY_FLAG_SHRINK     (1 << 6)
#define DENTRY_FLAG_LRU        (1 << 7)
#define DENTRY_FLAG_REFERENCED (1 << 8)

struct dentry_operations
{
    int (*d_revalidate)(struct dentry *, unsigned int flags);
};

#define D_REF_LOCKED (1UL << 63)

struct dentry
{
    unsigned long d_ref;
    struct spinlock d_lock;

    char *d_name;
    char d_inline_name[INLINE_NAME_MAX];
    fnv_hash_t d_name_hash;
    size_t d_name_length;
    struct inode *d_inode;

    struct dentry *d_parent;
    struct list_head d_parent_dir_node;
    struct list_head d_cache_node;
    struct list_head d_children_head;
    const struct dentry_operations *d_ops;
    union {
        struct rcu_head d_rcu;
        struct list_head d_lru;
    };

    unsigned long d_private;
#ifdef __cplusplus
    atomic<uint16_t> d_flags;
#else
    u16 d_flags;
#endif
};

struct dentry *dentry_open(char *path, struct dentry *base);
struct dentry *dentry_mount(const char *mountpoint, struct inode *inode);
void dentry_init();
void dput(struct dentry *d);
void dget(struct dentry *d);
struct inode;
struct dentry *dentry_create(const char *name, struct inode *inode, struct dentry *parent,
                             u16 flags
#ifdef __cplusplus
                             = 0
#endif
);
char *d_path(const struct path *path, char *buf, unsigned int buflen);

extern seqlock_t rename_lock;

/**
 * @brief Finish a VFS lookup
 *
 * @param dentry Dentry to finish
 * @param inode Lookup's result
 */
void d_finish_lookup(struct dentry *dentry, struct inode *inode);

void d_complete_negative(struct dentry *dentry);

static inline bool d_is_negative(struct dentry *dentry)
{
    return dentry->d_flags & DENTRY_FLAG_NEGATIVE;
}

void d_positiveize(struct dentry *dentry, struct inode *inode);

__always_inline bool dentry_is_dir(const struct dentry *d)
{
    return S_ISDIR(d->d_inode->i_mode);
}

__always_inline bool dentry_is_symlink(const struct dentry *d)
{
    return S_ISLNK(d->d_inode->i_mode);
}

struct dcache_scan_result
{
    unsigned long scanned_bytes;
    unsigned long scanned_objs;
};

struct dcache_shrink_result
{
    unsigned long to_shrink_bytes;
    unsigned long to_shrink_objs;
    struct list_head reclaim_list;
};

enum lru_walk_ret scan_dcache_lru_one(struct lru_list *lru, struct list_head *object, void *data);
enum lru_walk_ret shrink_dcache_lru_one(struct lru_list *lru, struct list_head *object, void *data);

void dentry_shrink_subtree(struct dentry *dentry);

/**
 * @brief Do the final unref on a whole subtree
 * Should _only_ be used by in-memory filesystems that use the dcache as their directories.
 *
 * @param dentry Root dentry
 */
void dentry_unref_subtree(struct dentry *dentry);

__END_CDECLS

#ifdef __cplusplus

#include <onyx/string_view.hpp>

using dentry_lookup_flags_t = uint16_t;

#define DENTRY_LOOKUP_UNLOCKED (1 << 0) /* To be used when inserting or already holding a lock */

dentry *dentry_lookup_internal(std::string_view v, dentry *dir, dentry_lookup_flags_t flags = 0);

void dentry_destroy(dentry *d);
dentry *dentry_parent(dentry *dir);
bool dentry_is_empty(dentry *dir);

class auto_dentry
{
private:
    dentry *d{nullptr};

    void ref() const
    {
        if (d)
            dget(d);
    }

    void unref() const
    {
        if (d)
            dput(d);
    }

public:
    auto_dentry() = default;

    auto_dentry(dentry *_f) : d{_f}
    {
    }

    ~auto_dentry()
    {
        if (d)
            dput(d);
    }

    auto_dentry &operator=(const auto_dentry &rhs)
    {
        if (&rhs == this)
            return *this;

        unref();

        if (rhs.d)
        {
            rhs.ref();
            d = rhs.d;
        }

        return *this;
    }

    auto_dentry(const auto_dentry &rhs)
    {
        if (&rhs == this)
            return;

        unref();

        if (rhs.d)
        {
            rhs.ref();
            d = rhs.d;
        }
    }

    auto_dentry &operator=(auto_dentry &&rhs)
    {
        if (&rhs == this)
            return *this;

        unref();
        d = rhs.d;
        rhs.d = nullptr;

        return *this;
    }

    auto_dentry(auto_dentry &&rhs)
    {
        if (&rhs == this)
            return;

        d = rhs.d;
        rhs.d = nullptr;
    }

    dentry *get_dentry()
    {
        return d;
    }

    dentry *release()
    {
        auto ret = d;
        d = nullptr;
        return ret;
    }

    operator bool() const
    {
        return d != nullptr;
    }
};

/**
 * @brief Trim the dentry caches
 *
 */
void dentry_trim_caches();

__always_inline bool dentry_is_mountpoint(const dentry *dir)
{
    return dir->d_flags & DENTRY_FLAG_MOUNTPOINT;
}

__always_inline bool dentry_involved_with_mount(dentry *d)
{
    return d->d_flags & (DENTRY_FLAG_MOUNTPOINT | DENTRY_FLAG_MOUNT_ROOT);
}

/**
 * @brief Fail a dentry lookup
 *
 * @param d Dentry
 */
void dentry_fail_lookup(dentry *d);

/**
 * @brief Complete a dentry lookup
 *
 * @param d Dentry
 */
void dentry_complete_lookup(dentry *d);

dentry *__dentry_parent(dentry *dir);
bool dentry_does_not_have_parent(dentry *dir, dentry *to_not_have);
void dentry_do_unlink(dentry *entry);
void dentry_rename(dentry *dent, const char *name, dentry *parent, dentry *dst);
void dentry_move(dentry *target, dentry *new_parent);

#endif

#endif
