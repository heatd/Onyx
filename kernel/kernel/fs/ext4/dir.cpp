/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <onyx/compiler.h>
#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/log.h>
#include <onyx/pagecache.h>
#include <onyx/panic.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include "ext4.h"

size_t ext4_calculate_dirent_size(size_t len_name)
{
    size_t dirent_size = sizeof(ext4_dir_entry_t) - (255 - len_name);

    /* Dirent sizes need to be 4-byte aligned */

    if (dirent_size % 4)
        dirent_size += 4 - dirent_size % 4;

    return dirent_size;
}

uint8_t ext4_file_type_to_type_indicator(uint16_t mode)
{
    if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_DIR)
        return EXT4_FT_DIR;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_REGFILE)
        return EXT4_FT_REG_FILE;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_BLOCKDEV)
        return EXT4_FT_BLKDEV;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_CHARDEV)
        return EXT4_FT_CHRDEV;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_SYMLINK)
        return EXT4_FT_SYMLINK;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_FIFO)
        return EXT4_FT_FIFO;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_UNIX_SOCK)
        return EXT4_FT_SOCK;
    else
        return EXT4_FT_UNKNOWN;
}

/**
 * @brief Tries to validate the directory entry as much as possible
 *
 * @param entry Pointer to a dir entry
 * @param offset Offset of the directory entry, inside the block
 * @return True if valid, else false.
 */
bool ext4_superblock::valid_dirent(const ext4_dir_entry_t *entry, size_t offset)
{
    // Check if we have space for a minimal directory entry
    const size_t remaining_block = block_size - offset;
    if (remaining_block < EXT4_MIN_DIR_ENTRY_LEN)
        return false;

    // From now on, we know the base directory entry (w/o the name) is valid

    // Check if the size of the directory entry is valid within the block
    if (entry->rec_len > remaining_block)
        return false;

    const size_t required_size = entry->name_len + EXT4_MIN_DIR_ENTRY_LEN;

    if (entry->rec_len < required_size)
        return false;

    // Dirent sizes need to be 4 byte aligned
    if (entry->rec_len % 4)
        return false;

    return true;
}

int ext4_add_direntry(const char *name, uint32_t inum, struct ext4_inode *ino, inode *dir,
                      ext4_superblock *fs)
{
    uint8_t *buffer;
    uint8_t *buf = buffer = (uint8_t *) zalloc(fs->block_size);
    if (!buf)
        return errno = ENOMEM, -1;

    if (inum == 0)
        panic("Bad inode number passed to ext4_add_direntry");

    size_t off = 0;

    ext4_dir_entry_t entry;

    size_t dirent_size = ext4_calculate_dirent_size(strlen(name));

    entry.inode = inum;
    entry.name_len = strlen(name);

    entry.file_type = ext4_file_type_to_type_indicator(ino->i_mode);

    strlcpy(entry.name, name, sizeof(entry.name));

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
                ext4_dir_entry_t *e = (ext4_dir_entry_t *) buf;

                if (!fs->valid_dirent(e, i))
                {
                    free(buffer);
                    fs->error("Invalid directory entry");
                    return -EIO;
                }

                size_t actual_size = ext4_calculate_dirent_size(e->name_len);

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

                    if (st = file_write_cache(buffer, fs->block_size, dir, off); st < 0)
                    {
                        free(buffer);
                        return st;
                    }

                    free(buffer);

                    return 0;
                }
                else if (e->rec_len > actual_size && e->rec_len - actual_size >= dirent_size)
                {
                    ext4_dir_entry_t *d = (ext4_dir_entry_t *) (buf + actual_size);
                    entry.rec_len = e->rec_len - actual_size;
                    e->rec_len = actual_size;
                    memcpy(d, &entry, dirent_size);

                    if (st = file_write_cache(buffer, fs->block_size, dir, off); st < 0)
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

            if (int st = file_write_cache(buf, fs->block_size, dir, off); st < 0)
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

void ext4_unlink_dirent(ext4_dir_entry_t *before, ext4_dir_entry_t *entry)
{
    /* If we're not the first dirent on the block, adjust the reclen
     * so it points to the next dirent(or the end of the block).
     */
    ext4_dir_entry_t *next = (ext4_dir_entry_t *) ((char *) entry + entry->rec_len);

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

int ext4_remove_direntry(uint32_t inum, struct inode *dir, struct ext4_superblock *fs)
{
    int st = -ENOENT;
    uint8_t *buf_start;
    uint8_t *buf = buf_start = (uint8_t *) zalloc(fs->block_size);
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

        ext4_dir_entry_t *before = nullptr;
        for (size_t i = 0; i < fs->block_size;)
        {
            ext4_dir_entry_t *e = (ext4_dir_entry_t *) buf;

            if (e->inode == inum)
            {
                /* We found the inode, unlink it. */
                ext4_unlink_dirent(before, e);

                st = 0;

                if (file_write_cache(buf, fs->block_size, dir, off) < 0)
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

int ext4_file_present(inode *inode, const char *name, ext4_superblock *fs)
{
    ext4_dirent_result res;

    int st = ext4_retrieve_dirent(inode, name, fs, &res);

    if (st < 0 && st != -ENOENT)
        return -EIO;
    else if (st == 1)
    {
        free(res.buf);
    }

    return st != -ENOENT;
}

int ext4_retrieve_dirent(inode *inode, const char *name, ext4_superblock *fs,
                         ext4_dirent_result *res)
{
    int st = -ENOENT;
    char *buf = static_cast<char *>(zalloc(fs->block_size));
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
            ext4_dir_entry_t *entry = (ext4_dir_entry_t *) b;
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

int ext4_link(struct inode *target, const char *name, struct inode *dir)
{
    assert(target->i_sb == dir->i_sb);

    struct ext4_superblock *fs = ext4_superblock_from_inode(dir);

    struct ext4_inode *target_ino = ext4_get_inode_from_node(target);

    int st = ext4_file_present(dir, name, fs);
    if (st < 0)
    {
        return st;
    }
    else if (st == 1)
    {
        return -EEXIST;
    }

    unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    /* Blame past me for the inconsistency in return values */
    st = ext4_add_direntry(name, (uint32_t) target->i_inode, target_ino, dir, fs);

    if (st < 0)
    {
        thread_change_addr_limit(old);
        return -errno;
    }

    /* If we're linking a directory, this means we're part of a rename(). */

    if (target->i_type == VFS_TYPE_DIR && !!strcmp(name, ".") && !!strcmp(name, ".."))
    {
        /* Adjust .. to point to us */
        ext4_dirent_result res;
        st = ext4_retrieve_dirent(target, "..", fs, &res);

        if (st < 0)
        {
            thread_change_addr_limit(old);
            return st;
        }

        ext4_dir_entry_t *dentry = (ext4_dir_entry_t *) (res.buf + res.block_off);
        dentry->inode = (uint32_t) dir->i_inode;

        st = file_write_cache(dentry, sizeof(ext4_dir_entry_t), target, res.file_off);
        inode_inc_nlink(dir);
    }

    thread_change_addr_limit(old);

    if (st < 0)
    {
        return -errno;
    }

    fs->update_inode(target_ino, (ext4_inode_no) target->i_inode);

    return 0;
}

int ext4_link_fops(struct file *_target, const char *name, struct dentry *_dir)
{
    return ext4_link(_target->f_ino, name, _dir->d_inode);
}

bool ext4_is_standard_dir_link(ext4_dir_entry_t *entry)
{
    if (!memcmp(entry->name, ".", entry->name_len))
        return true;
    if (!memcmp(entry->name, "..", entry->name_len))
        return true;
    return false;
}

int ext4_dir_empty(struct inode *ino)
{
    struct ext4_superblock *fs = ext4_superblock_from_inode(ino);

    int st = 1;
    char *buf = (char *) zalloc(fs->block_size);
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
            ext4_dir_entry_t *entry = (ext4_dir_entry_t *) b;

            if (entry->inode != 0 && !ext4_is_standard_dir_link(entry))
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

int ext4_unlink(const char *name, int flags, struct dentry *dir)
{
    struct inode *ino = dir->d_inode;
    struct ext4_superblock *fs = ext4_superblock_from_inode(ino);

    struct ext4_dirent_result res;
    int st = ext4_retrieve_dirent(ino, name, fs, &res);

    if (st < 0)
    {
        return st;
    }

    ext4_dir_entry_t *ent = (ext4_dir_entry_t *) (res.buf + res.block_off);

    struct inode *target = ext4_get_inode(fs, ent->inode);

    if (!target)
    {
        free(res.buf);
        return -ENOMEM;
    }

    if (target->i_type == VFS_TYPE_DIR)
    {
        if (!(flags & AT_REMOVEDIR))
        {
            inode_unref(target);
            free(res.buf);
            return -EISDIR;
        }

        if (!(flags & UNLINK_VFS_DONT_TEST_EMPTY) && ext4_dir_empty(target) == 0)
        {
            inode_unref(target);
            free(res.buf);
            return -ENOTEMPTY;
        }
    }

    ext4_dir_entry_t *before = nullptr;

    /* Now, unlink the dirent */
    if (res.block_off != 0)
    {
        for (char *b = res.buf; b < res.buf + res.block_off;)
        {
            ext4_dir_entry_t *dir = (ext4_dir_entry_t *) b;
            if ((b - res.buf) + dir->rec_len == res.block_off)
            {
                before = dir;
                break;
            }

            b += dir->rec_len;
        }

        assert(before != nullptr);
    }

    ext4_unlink_dirent(before, (ext4_dir_entry_t *) (res.buf + res.block_off));

    /* Flush to disk */
    /* TODO: Maybe we can optimize things by not flushing the whole block? */
    auto old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
    if (st = file_write_cache(res.buf, fs->block_size, ino, res.file_off - res.block_off); st < 0)
    {
        thread_change_addr_limit(old);
        printk("ext4: error %d\n", st);
        close_vfs(target);
        return -EIO;
    }

    thread_change_addr_limit(old);

    free(res.buf);

    close_vfs(target);

    return 0;
}
