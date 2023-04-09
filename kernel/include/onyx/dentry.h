/*
 * Copyright (c) 2018 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_DENTRY_H
#define _ONYX_DENTRY_H

#include <stddef.h>
#include <stdint.h>

#include <onyx/fnv.h>
#include <onyx/limits.h>
#include <onyx/list.h>
#include <onyx/rwlock.h>
#include <onyx/vfs.h>

#include <onyx/atomic.hpp>

#define INLINE_NAME_MAX 40

#define DENTRY_FLAG_MOUNTPOINT (1 << 0)
#define DENTRY_FLAG_MOUNT_ROOT (1 << 1)
#define DENTRY_FLAG_PENDING    (1 << 2)
#define DENTRY_FLAG_FAILED     (1 << 3)

struct dentry
{
    unsigned long d_ref;
    rwslock d_lock;

    char *d_name;
    char d_inline_name[INLINE_NAME_MAX];
    fnv_hash_t d_name_hash;
    size_t d_name_length;
    struct inode *d_inode;

    struct dentry *d_parent;
    struct list_head d_parent_dir_node;
    struct list_head d_cache_node;
    struct list_head d_children_head;
    struct dentry *d_mount_dentry;
    atomic<uint16_t> d_flags;
};

struct dentry *dentry_open(char *path, struct dentry *base);
struct dentry *dentry_mount(const char *mountpoint, struct inode *inode);
void dentry_init();
void dentry_put(struct dentry *d);
void dentry_get(struct dentry *d);
struct inode;
struct dentry *dentry_create(const char *name, struct inode *inode, struct dentry *parent);
char *dentry_to_file_name(struct dentry *dentry);

#ifdef __cplusplus

#include <onyx/string_view.hpp>

using dentry_lookup_flags_t = uint16_t;

#define DENTRY_LOOKUP_UNLOCKED            (1 << 0) /* To be used when inserting or already holding a lock */
#define DENTRY_LOOKUP_DONT_TRY_TO_RESOLVE (1 << 1) /* Don't try to resolve cache misses */

dentry *dentry_lookup_internal(std::string_view v, dentry *dir, dentry_lookup_flags_t flags = 0);

struct nameidata;
dentry *dentry_resolve(nameidata &data);
void dentry_destroy(dentry *d);
dentry *dentry_parent(dentry *dir);
bool dentry_is_empty(dentry *dir);

class auto_dentry
{
private:
    dentry *d;

    void ref() const
    {
        if (d)
            dentry_get(d);
    }

    void unref() const
    {
        if (d)
            dentry_put(d);
    }

public:
    auto_dentry() = default;

    auto_dentry(dentry *_f) : d{_f}
    {
    }

    ~auto_dentry()
    {
        if (d)
            dentry_put(d);
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

__always_inline bool dentry_is_dir(const dentry *d)
{
    return S_ISDIR(d->d_inode->i_mode);
}

__always_inline bool dentry_is_symlink(const dentry *d)
{
    return S_ISLNK(d->d_inode->i_mode);
}

__always_inline bool dentry_is_mountpoint(const dentry *dir)
{
    return dir->d_flags & DENTRY_FLAG_MOUNTPOINT;
}

__always_inline bool dentry_involved_with_mount(dentry *d)
{
    return d->d_flags & (DENTRY_FLAG_MOUNTPOINT | DENTRY_FLAG_MOUNT_ROOT);
}

expected<dentry *, int> dentry_create_pending_lookup(const char *name, inode *ino, dentry *parent,
                                                     bool check_existance = true);

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
void dentry_rename(dentry *dent, const char *name);
void dentry_move(dentry *target, dentry *new_parent);

#endif

#endif
