/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/log.h>
#include <onyx/mm/slab.h>
#include <onyx/pagecache.h>
#include <onyx/panic.h>
#include <onyx/types.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include <uapi/dirent.h>
#include <uapi/fcntl.h>

#include "ext2.h"

const unsigned int direct_block_count = 12;

static inline void __ext2_update_ctime(struct ext2_inode *ino)
{
    ino->i_ctime = (uint32_t) clock_get_posix_time();
}

/**
 * @brief Reads metadata blocks from the filesystem using sb_read_block
 *
 * @param block Starting block
 * @param number_of_blocks Number of blocks
 * @param bufs Pointer to an array of N auto_block_buf's
 * @return 0 on success, negative error codes
 */
int ext2_superblock::read_blocks(ext2_block_no block, ext2_block_no number_of_blocks,
                                 auto_block_buf *bufs)
{
    for (ext2_block_no i = 0; i < number_of_blocks; i++)
    {
        bufs[i] = sb_read_block(this, block + i);
        if (!bufs[i])
        {
            for (ext2_block_no j = 0; j < i; j++)
            {
                bufs[j].reset(nullptr);
                return -errno;
            }
        }
    }

    return 0;
}

/**
 * @brief Read an ext2_inode from disk
 *
 * @param nr The inode number
 * @return A pointer to the inode number
 */
ext2_inode *ext2_superblock::get_inode(ext2_inode_no inode) const
{
    uint32_t bg_no = ext2_inode_number_to_bg(inode, this);
    uint32_t index = (inode - 1) % inodes_per_block_group;
    uint32_t inodes_per_block = block_size / inode_size;
    uint32_t block = index / inodes_per_block;
    uint32_t off = (index % inodes_per_block) * inode_size;

    assert(bg_no < number_of_block_groups);

    const auto &bg = block_groups[bg_no];

    auto buf = bg.get_inode_table(this, block);
    if (!buf)
    {
        error("Error reading inode table.");
        printk("Tried to read block %u\n", bg.get_bgd()->block_usage_addr);
        return nullptr;
    }

    ext2_inode *ino = (ext2_inode *) malloc(inode_size);
    if (!ino)
        return nullptr;

    ext2_inode *on_disk = (ext2_inode *) ((char *) block_buf_data(buf) + off);
    memcpy(ino, on_disk, min(inode_size, (u16) sizeof(struct ext2_inode)));
    return ino;
}

/**
 * @brief Updates an inode on disk
 *
 * @param ino Pointer to ext2_inode
 * @param inode_no Inode number
 * @param in_sync If this is part of a sync/fsync call (i.e do we need to write the buffer back
 * immediately.)
 */
void ext2_superblock::update_inode(const ext2_inode *ino, ext2_inode_no inode_no, bool in_sync)
{
    assert(inode_no != 0);
    uint32_t bg_no = ext2_inode_number_to_bg(inode_no, this);
    uint32_t index = (inode_no - 1) % inodes_per_block_group;
    uint32_t inodes_per_block = block_size / inode_size;
    uint32_t block = index / inodes_per_block;
    uint32_t off = (index % inodes_per_block) * inode_size;

    assert(bg_no < number_of_block_groups);

    const auto &bg = block_groups[bg_no];

    auto buf = bg.get_inode_table(this, block);
    if (!buf)
    {
        error("Error reading inode table.");
        printk("Tried to read block %u\n", bg.get_bgd()->block_usage_addr);
        return;
    }

    ext2_inode *on_disk = (ext2_inode *) ((char *) block_buf_data(buf) + off);
    memcpy(on_disk, ino, min(inode_size, (u16) sizeof(struct ext2_inode)));

    block_buf_dirty(buf);

    if (in_sync)
        block_buf_sync(buf);
}

void ext2_dirty_sb(ext2_superblock *fs)
{
    block_buf_dirty(fs->sb_bb);
}

size_t ext2_calculate_dirent_size(size_t len_name)
{
    size_t dirent_size = sizeof(ext2_dir_entry_t) - (255 - len_name);

    /* Dirent sizes need to be 4-byte aligned */

    if (dirent_size % 4)
        dirent_size += 4 - dirent_size % 4;

    return dirent_size;
}

uint8_t ext2_file_type_to_type_indicator(uint16_t mode)
{
    if (EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_DIR)
        return EXT2_FT_DIR;
    else if (EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_REGFILE)
        return EXT2_FT_REG_FILE;
    else if (EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_BLOCKDEV)
        return EXT2_FT_BLKDEV;
    else if (EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_CHARDEV)
        return EXT2_FT_CHRDEV;
    else if (EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_SYMLINK)
        return EXT2_FT_SYMLINK;
    else if (EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_FIFO)
        return EXT2_FT_FIFO;
    else if (EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_UNIX_SOCK)
        return EXT2_FT_SOCK;
    else
        return EXT2_FT_UNKNOWN;
}

/**
 * @brief Tries to validate the directory entry as much as possible
 *
 * @param entry Pointer to a dir entry
 * @param offset Offset of the directory entry, inside the block
 * @return True if valid, else false.
 */
bool ext2_superblock::valid_dirent(const ext2_dir_entry_t *entry, size_t offset)
{
    // Check if we have space for a minimal directory entry
    const size_t remaining_block = block_size - offset;
    if (remaining_block < EXT2_MIN_DIR_ENTRY_LEN)
        return false;

    // From now on, we know the base directory entry (w/o the name) is valid

    // Check if the size of the directory entry is valid within the block
    if (entry->rec_len > remaining_block)
        return false;

    const size_t required_size = entry->name_len + EXT2_MIN_DIR_ENTRY_LEN;

    if (entry->rec_len < required_size)
        return false;

    // Dirent sizes need to be 4 byte aligned
    if (entry->rec_len % 4)
        return false;

    return true;
}

int ext2_add_direntry(const char *name, uint32_t inum, struct ext2_inode *ino, inode *dir,
                      ext2_superblock *fs)
{
    uint8_t *buffer;
    uint8_t *buf = buffer = (uint8_t *) kcalloc(fs->block_size, 1, GFP_NOFS);
    if (!buf)
        return -ENOMEM;

    if (inum == 0)
        panic("Bad inode number passed to ext2_add_direntry");

    size_t off = 0;

    ext2_dir_entry_t entry;

    size_t dirent_size = ext2_calculate_dirent_size(strlen(name));

    entry.inode = inum;
    entry.name_len = strlen(name);
    entry.file_type = ext2_file_type_to_type_indicator(ino->i_mode);
    strlcpy(entry.name, name, entry.name_len + 1);

    while (true)
    {
        if (off < dir->i_size)
        {
            auto old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

            auto st = file_read_cache(buffer, fs->block_size, dir, off);

            thread_change_addr_limit(old);

            if (st < 0)
            {
                free(buffer);
                return st;
            }

            for (size_t i = 0; i < fs->block_size;)
            {
                ext2_dir_entry_t *e = (ext2_dir_entry_t *) buf;

                if (!fs->valid_dirent(e, i))
                {
                    free(buffer);
                    fs->error("Invalid directory entry");
                    return -EIO;
                }

                size_t actual_size = ext2_calculate_dirent_size(e->name_len);

#if 0
				printk("Entry %s size %u - actual size %lu\n", e->name, e->size, actual_size);
#endif

                if (e->inode == 0 && e->rec_len >= dirent_size)
                {
                    /* This direntry is unused, so use it */
                    e->inode = entry.inode;
                    e->name_len = entry.name_len;
                    strlcpy(e->name, entry.name, sizeof(entry.name));
                    e->file_type = entry.file_type;

                    if (st = file_write_cache_unlocked(buffer, fs->block_size, dir, off); st < 0)
                    {
                        free(buffer);
                        return st;
                    }

                    free(buffer);

                    return 0;
                }
                else if (e->rec_len > actual_size && e->rec_len - actual_size >= dirent_size)
                {
                    ext2_dir_entry_t *d = (ext2_dir_entry_t *) (buf + actual_size);
                    entry.rec_len = e->rec_len - actual_size;
                    e->rec_len = actual_size;
                    memcpy(d, &entry, dirent_size);

                    if (st = file_write_cache_unlocked(buffer, fs->block_size, dir, off); st < 0)
                    {
                        free(buffer);
                        return st;
                    }

                    free(buffer);

                    return 0;
                }

                buf += e->rec_len;
                i += e->rec_len;
            }
        }
        else
        {
            entry.rec_len = fs->block_size;
            memcpy(buf, &entry, dirent_size);

            if (int st = file_write_cache_unlocked(buf, fs->block_size, dir, off); st < 0)
            {
                return st;
            }

            break;
        }

        off += fs->block_size;
        buf = buffer;
    }

    free(buffer);
    return 0;
}

void ext2_unlink_dirent(ext2_dir_entry_t *before, ext2_dir_entry_t *entry)
{
    /* If we're not the first dirent on the block, adjust the reclen
     * so it points to the next dirent(or the end of the block).
     */
    ext2_dir_entry_t *next = (ext2_dir_entry_t *) ((char *) entry + entry->rec_len);

    if (before)
    {
#if 0
		printk("Old size: %u\n", before->size);
		printk("Next: %p\nBefore: %p\n", next, before);
#endif
        before->rec_len = (unsigned long) next - (unsigned long) before;
#if 0
		printk("New size: %u\n", before->size);
#endif
    }

    /* Mark the entry as unused */
    entry->inode = 0;
}

int ext2_remove_direntry(uint32_t inum, struct inode *dir, struct ext2_superblock *fs)
{
    int st = -ENOENT;
    uint8_t *buf_start;
    uint8_t *buf = buf_start = (uint8_t *) kcalloc(fs->block_size, 1, GFP_NOFS);
    if (!buf)
        return errno = ENOMEM, -1;

    size_t off = 0;

    while (off < dir->i_size)
    {
        if (file_read_cache(buf, fs->block_size, dir, off) < 0)
        {
            free(buf);
            return -errno;
        }

        ext2_dir_entry_t *before = nullptr;
        for (size_t i = 0; i < fs->block_size;)
        {
            ext2_dir_entry_t *e = (ext2_dir_entry_t *) buf;

            if (e->inode == inum)
            {
                /* We found the inode, unlink it. */
                ext2_unlink_dirent(before, e);

                st = 0;

                if (file_write_cache_unlocked(buf, fs->block_size, dir, off) < 0)
                {
                    st = -errno;
                }

                goto out;
            }

            before = e;
            buf += e->rec_len;
            i += e->rec_len;
        }

        off += fs->block_size;
        buf = buf_start;
    }

out:
    free(buf_start);
    return st;
}

int ext2_file_present(inode *inode, const char *name, ext2_superblock *fs)
{
    ext2_dirent_result res;

    int st = ext2_retrieve_dirent(inode, name, fs, &res);

    if (st < 0 && st != -ENOENT)
        return -EIO;
    else if (st == 1)
    {
        free(res.buf);
    }

    return st != -ENOENT;
}

int ext2_retrieve_dirent(inode *inode, const char *name, ext2_superblock *fs,
                         ext2_dirent_result *res)
{
    int st = -ENOENT;
    char *buf = static_cast<char *>(kcalloc(fs->block_size, 1, GFP_NOFS));
    if (!buf)
        return -ENOMEM;

    size_t off = 0;

    while (off < inode->i_size)
    {
        auto old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

        ssize_t read_res = file_read_cache(buf, fs->block_size, inode, off);

        thread_change_addr_limit(old);

        if (read_res < 0)
        {
            st = -errno;
            goto out;
        }

        for (char *b = buf; b < buf + fs->block_size;)
        {
            ext2_dir_entry_t *entry = (ext2_dir_entry_t *) b;
            if (entry->rec_len == 0)
            {
                fs->error("Directory entry has size 0");
                st = -EIO;
                goto out;
            }

            if (entry->inode == 0)
            {
                b += entry->rec_len;
                continue;
            }

            if (entry->name_len == strlen(name) && !memcmp(entry->name, name, entry->name_len))
            {
                res->block_off = b - buf;
                res->file_off = off + res->block_off;
                res->buf = buf;
                st = 1;
                goto out;
            }

            b += entry->rec_len;
        }

        off += fs->block_size;
    }

out:
    if (st != 1)
        free(buf);
    return st;
}

int ext2_link(struct inode *target, const char *name, struct inode *dir)
{
    assert(target->i_sb == dir->i_sb);
    struct ext2_superblock *fs = ext2_superblock_from_inode(dir);
    struct ext2_inode *target_ino = ext2_get_inode_from_node(target);

    int st = ext2_file_present(dir, name, fs);
    if (st < 0)
        return st;
    else if (st == 1)
        return -EEXIST;

    unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
    /* Blame past me for the inconsistency in return values */
    st = ext2_add_direntry(name, (uint32_t) target->i_inode, target_ino, dir, fs);
    if (st < 0)
    {
        thread_change_addr_limit(old);
        return -errno;
    }

    /* If we're linking a directory, this means we're part of a rename(). */
    if (S_ISDIR(target->i_mode) && !!strcmp(name, ".") && !!strcmp(name, ".."))
    {
        /* Adjust .. to point to us */
        ext2_dirent_result res;
        st = ext2_retrieve_dirent(target, "..", fs, &res);
        if (st < 0)
        {
            thread_change_addr_limit(old);
            return st;
        }

        ext2_dir_entry_t *dentry = (ext2_dir_entry_t *) (res.buf + res.block_off);
        dentry->inode = (uint32_t) dir->i_inode;

        st = file_write_cache_unlocked(dentry, sizeof(ext2_dir_entry_t), target, res.file_off);
    }

    thread_change_addr_limit(old);

    if (st < 0)
        return -errno;
    return 0;
}

int ext2_link_fops(struct dentry *old_dentry, struct dentry *new_dentry)
{
    return ext2_link(old_dentry->d_inode, new_dentry->d_name, new_dentry->d_parent->d_inode);
}

struct inode *ext2_load_inode_from_disk(uint32_t inum, struct ext2_superblock *fs)
{
    struct ext2_inode *inode = fs->get_inode(inum);
    if (!inode)
        return nullptr;

    struct inode *node = ext2_fs_ino_to_vfs_ino(inode, inum, fs);
    if (!node)
    {
        free(inode);
        return errno = ENOMEM, nullptr;
    }

    return node;
}

bool ext2_is_standard_dir_link(ext2_dir_entry_t *entry)
{
    if (!memcmp(entry->name, ".", entry->name_len))
        return true;
    if (!memcmp(entry->name, "..", entry->name_len))
        return true;
    return false;
}

int ext2_dir_empty(struct inode *ino)
{
    struct ext2_superblock *fs = ext2_superblock_from_inode(ino);

    int st = 1;
    char *buf = (char *) kcalloc(fs->block_size, 1, GFP_NOFS);
    if (!buf)
        return -ENOMEM;

    size_t off = 0;

    while (off < ino->i_size)
    {
        unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

        if (file_read_cache(buf, fs->block_size, ino, off) < 0)
            return -errno;

        thread_change_addr_limit(old);

        for (char *b = buf; b < buf + fs->block_size;)
        {
            ext2_dir_entry_t *entry = (ext2_dir_entry_t *) b;

            if (entry->inode != 0 && !ext2_is_standard_dir_link(entry))
            {
                st = 0;
                goto out;
            }

            b += entry->rec_len;
        }

        off += fs->block_size;
    }

out:
    free(buf);
    return st;
}

int ext2_unlink(const char *name, int flags, struct dentry *dir)
{
    struct inode *ino = dir->d_inode;
    struct ext2_superblock *fs = ext2_superblock_from_inode(ino);

    struct ext2_dirent_result res;
    int st = ext2_retrieve_dirent(ino, name, fs, &res);

    if (st < 0)
    {
        return st;
    }

    ext2_dir_entry_t *ent = (ext2_dir_entry_t *) (res.buf + res.block_off);

    struct inode *target = ext2_get_inode(fs, ent->inode);

    if (!target)
    {
        free(res.buf);
        return -ENOMEM;
    }

    if (S_ISDIR(target->i_mode))
    {
        if (!(flags & AT_REMOVEDIR))
        {
            inode_unref(target);
            free(res.buf);
            return -EISDIR;
        }

        if (!(flags & UNLINK_VFS_DONT_TEST_EMPTY) && ext2_dir_empty(target) == 0)
        {
            inode_unref(target);
            free(res.buf);
            return -ENOTEMPTY;
        }
    }

    ext2_dir_entry_t *before = nullptr;

    /* Now, unlink the dirent */
    if (res.block_off != 0)
    {
        for (char *b = res.buf; b < res.buf + res.block_off;)
        {
            ext2_dir_entry_t *dir = (ext2_dir_entry_t *) b;
            if ((b - res.buf) + dir->rec_len == res.block_off)
            {
                before = dir;
                break;
            }

            b += dir->rec_len;
        }

        assert(before != nullptr);
    }

    ext2_unlink_dirent(before, (ext2_dir_entry_t *) (res.buf + res.block_off));

    /* Flush to disk */
    /* TODO: Maybe we can optimize things by not flushing the whole block? */
    auto old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
    if (st = file_write_cache_unlocked(res.buf, fs->block_size, ino, res.file_off - res.block_off);
        st < 0)
    {
        thread_change_addr_limit(old);
        printk("ext2: error %d\n", st);
        close_vfs(target);
        return -EIO;
    }

    thread_change_addr_limit(old);

    free(res.buf);

    close_vfs(target);

    return 0;
}

int ext2_fallocate(int mode, off_t off, off_t len, struct file *ino)
{
    return -ENOSYS;
}

static int ext2_flush_dirents(ext2_dirent_result *res, struct inode *ino)
{
    auto old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
    if (int st = file_write_cache_unlocked(res->buf, ((ext2_superblock *) ino->i_sb)->block_size,
                                           ino, res->file_off - res->block_off);
        st < 0)
    {
        thread_change_addr_limit(old);
        free(res->buf);
        return -EIO;
    }

    thread_change_addr_limit(old);
    free(res->buf);
    return 0;
}

static int ext2_raw_unlink(struct dentry *dir, struct dentry *dentry)
{
    struct inode *ino = dir->d_inode;
    struct ext2_dirent_result res;
    DCHECK(!d_is_negative(dentry) && dentry->d_parent == dir);

    int st = ext2_retrieve_dirent(ino, dentry->d_name, (ext2_superblock *) ino->i_sb, &res);
    if (st < 0)
        return st;

    ext2_dir_entry_t *before = nullptr;
    /* Now, unlink the dirent */
    if (res.block_off != 0)
    {
        for (char *b = res.buf; b < res.buf + res.block_off;)
        {
            ext2_dir_entry_t *dir = (ext2_dir_entry_t *) b;
            if ((b - res.buf) + dir->rec_len == res.block_off)
            {
                before = dir;
                break;
            }

            b += dir->rec_len;
        }

        assert(before != nullptr);
    }

    ext2_unlink_dirent(before, (ext2_dir_entry_t *) (res.buf + res.block_off));
    return ext2_flush_dirents(&res, ino);
}

static int ext2_replace_dirent(struct dentry *src, struct dentry *dst_dir, struct dentry *dst)
{
    struct inode *ino = dst_dir->d_inode;
    struct inode *target_inode = src->d_inode;
    struct ext2_dirent_result res;
    int st = ext2_retrieve_dirent(ino, dst->d_name, (ext2_superblock *) ino->i_sb, &res);
    if (st < 0)
        return st;

    ext2_dir_entry_t *ent = (ext2_dir_entry_t *) (res.buf + res.block_off);
    ent->inode = target_inode->i_inode;
    ent->file_type = ext2_file_type_to_type_indicator(target_inode->i_mode);

    if (st = ext2_flush_dirents(&res, ino); st < 0)
        return st;
    if (S_ISDIR(target_inode->i_mode))
    {
        /* If we renamed a directory, patch up .. */
        ext2_dirent_result res2;
        st = ext2_retrieve_dirent(target_inode, "..", (ext2_superblock *) ino->i_sb, &res2);
        if (st < 0)
            return st;

        ext2_dir_entry_t *dentry = (ext2_dir_entry_t *) (res2.buf + res2.block_off);
        dentry->inode = (uint32_t) ino->i_inode;
        st = ext2_flush_dirents(&res2, target_inode);
    }

    return st;
}

int ext2_rename(struct dentry *src_parent, struct dentry *src, struct dentry *dst_dir,
                struct dentry *dst)
{
    /* Note: we don't adjust nlinks until later on (to avoid disk activity). We partially adjust
     * them if failure happens for some reason (TODO). */
    int st = 0;
    st = ext2_raw_unlink(src_parent, src);
    if (st < 0)
        return st;

    // pr_info("ext2_rename: dst exists? %s\n", !d_is_negative(dst) ? "yes" : "no");

    if (d_is_negative(dst))
        st = ext2_link(src->d_inode, dst->d_name, dst_dir->d_inode);
    else
    {
        if (dentry_is_dir(dst) != dentry_is_dir(src))
            return -ENOTDIR;
        if (dentry_is_dir(dst) && !ext2_dir_empty(dst->d_inode))
            return -ENOTEMPTY;
        st = ext2_replace_dirent(src, dst_dir, dst);
        // pr_info("ext2_rename: dirent replaced\n");
    }

    if (st < 0)
        return st;

    /* Adjust nlinks */
    if (dentry_is_dir(src))
    {
        if (src_parent != dst_dir)
        {
            inode_dec_nlink(src_parent->d_inode);
            inode_inc_nlink(dst_dir->d_inode);
        }

        if (!d_is_negative(dst))
        {
            /* We're killing the inode */
            DCHECK(dst->d_inode->i_nlink == 2);
            inode_dec_nlink(dst->d_inode);
            if (src_parent == dst_dir)
                inode_dec_nlink(dst_dir->d_inode);
        }
    }

    if (!d_is_negative(dst))
        inode_dec_nlink(dst->d_inode);

    return 0;
}
