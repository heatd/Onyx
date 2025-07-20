/*
 * Copyright (c) 2017 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_SUPERBLOCK_H
#define _ONYX_SUPERBLOCK_H

#include <sys/statfs.h>

#include <onyx/list.h>
#include <onyx/lru.h>
#include <onyx/mm/shrinker.h>
#include <onyx/mutex.h>
#include <onyx/rcupdate.h>
#include <onyx/spinlock.h>
#include <onyx/types.h>

struct file;
struct bio_req;
struct blockdev;
struct mount;
struct fs_mount;

#define SB_FLAG_NODIRTY   (1 << 0)
#define SB_FLAG_IN_MEMORY (1 << 1)

struct super_ops
{
    int (*flush_inode)(struct inode *inode, bool in_sync);
    void (*evict_inode)(struct inode *inode);
    int (*statfs)(struct statfs *buf, struct superblock *sb);
    int (*umount)(struct mount *mnt);
    int (*shutdown)(struct superblock *sb);
};

struct superblock
{
    struct list_head s_inodes;
    struct spinlock s_ilock;
    unsigned long s_ref;
    void *s_helper;
    unsigned int s_block_size;
    const struct super_ops *s_ops;
    struct blockdev *s_bdev;
    dev_t s_devnr;
    unsigned long s_flags;
    struct mutex s_rename_lock;
    struct lru_list s_dcache_lru;
    union {
        struct shrinker s_shrinker;
        struct rcu_head s_rcu;
    };
    struct fs_mount *s_type;
};

__BEGIN_CDECLS

void superblock_init(struct superblock *sb);
struct inode *superblock_find_inode(struct superblock *sb, ino_t inode);
void superblock_add_inode_unlocked(struct superblock *sb, struct inode *inode);
void superblock_add_inode(struct superblock *sb, struct inode *inode);
void superblock_remove_inode(struct superblock *sb, struct inode *inode);
void superblock_kill(struct superblock *sb);
void sb_shutdown(struct superblock *sb);
int sb_generic_shutdown(struct superblock *sb);

struct page_iov;

int sb_read_bio(struct superblock *sb, struct page_iov *vec, size_t nr_vecs, size_t block_number);
int sb_write_bio(struct superblock *sb, struct page_iov *vec, size_t nr_vecs, size_t block_number,
                 void (*endio)(struct bio_req *), void *b_private);

bool sb_check_callbacks(struct superblock *sb);

__END_CDECLS

#endif
