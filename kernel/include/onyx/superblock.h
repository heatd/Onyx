/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_SUPERBLOCK_H
#define _ONYX_SUPERBLOCK_H

#include <sys/statfs.h>
#include <sys/types.h>

#include <onyx/list.h>
#include <onyx/mutex.h>
#include <onyx/spinlock.h>

struct file;

struct blockdev;

#define SB_FLAG_NODIRTY   (1 << 0)
#define SB_FLAG_IN_MEMORY (1 << 1)

struct superblock
{
    struct list_head s_inodes;
    struct spinlock s_ilock;
    unsigned long s_ref;
    void *s_helper;
    int (*flush_inode)(struct inode *inode);
    int (*kill_inode)(struct inode *inode);
    int (*statfs)(struct statfs *buf, superblock *sb);
    unsigned int s_block_size;
    struct blockdev *s_bdev;
    dev_t s_devnr;
    unsigned long s_flags;
    mutex s_rename_lock;
};

void superblock_init(struct superblock *sb);
struct inode *superblock_find_inode(struct superblock *sb, ino_t inode);
void superblock_add_inode_unlocked(struct superblock *sb, struct inode *inode);
void superblock_add_inode(struct superblock *sb, struct inode *inode);
void superblock_remove_inode(struct superblock *sb, struct inode *inode);
void superblock_kill(struct superblock *sb);

struct page_iov;

int sb_read_bio(struct superblock *sb, struct page_iov *vec, size_t nr_vecs, size_t block_number);
int sb_write_bio(struct superblock *sb, struct page_iov *vec, size_t nr_vecs, size_t block_number);

#endif
