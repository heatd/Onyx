/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include "ext4.h"

#include <alloca.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <onyx/buffer.h>
#include <onyx/compiler.h>
#include <onyx/crc32.h>
#include <onyx/cred.h>
#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/fs_mount.h>
#include <onyx/limits.h>
#include <onyx/log.h>
#include <onyx/pagecache.h>
#include <onyx/panic.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

struct inode *ext4_open(struct dentry *dir, const char *name);
off_t ext4_getdirent(struct dirent *buf, off_t off, struct file *f);
struct inode *ext4_creat(const char *path, int mode, struct dentry *dir);
char *ext4_readlink(struct file *ino);
void ext4_close(struct inode *ino);
struct inode *ext4_mknod(const char *name, mode_t mode, dev_t dev, struct dentry *dir);
struct inode *ext4_mkdir(const char *name, mode_t mode, struct dentry *dir);
int ext4_link_fops(struct file *target, const char *name, struct dentry *dir);
int ext4_fallocate(int mode, off_t off, off_t len, struct file *f);
int ext4_ftruncate(size_t len, struct file *f);
ssize_t ext4_readpage(struct page *page, size_t off, struct inode *ino);
ssize_t ext4_writepage(struct page *page, size_t off, struct inode *ino);
int ext4_prepare_write(inode *ino, struct page *page, size_t page_off, size_t offset, size_t len);
int ext4_link(struct inode *target, const char *name, struct inode *dir);
inode *ext4_symlink(const char *name, const char *dest, dentry *dir);

struct file_ops ext4_ops = {.open = ext4_open,
                            .close = ext4_close,
                            .getdirent = ext4_getdirent,
                            .creat = ext4_creat,
                            .link = ext4_link_fops,
                            .symlink = ext4_symlink,
                            .ftruncate = ext4_ftruncate,
                            .mkdir = ext4_mkdir,
                            .mknod = ext4_mknod,
                            .readlink = ext4_readlink,
                            .unlink = ext4_unlink,
                            .fallocate = ext4_fallocate,
                            .readpage = ext4_readpage,
                            .writepage = ext4_writepage,
                            .prepare_write = ext4_prepare_write};

/**
   Calculates the superblock's checksum.
   @param[in] Partition    Pointer to the opened partition.
   @param[in] Sb           Pointer to the superblock.
   @return The superblock's checksum.
**/
static uint32_t ext4_calculate_sb_csum(const ext4_superblock *sb)
{
    return ext4_calculate_csum(sb, sb->sb, offsetof(superblock_t, s_checksum), ~0U);
}

void ext4_dirty_sb(ext4_superblock *fs)
{
    if (EXT4_HAS_METADATA_CSUM(fs))
        fs->sb->s_checksum = ext4_calculate_sb_csum(fs);
    block_buf_dirty(fs->sb_bb);
}

/**
   Verifies that the superblock's checksum is valid.
   @param[in] Partition    Pointer to the opened partition.
   @param[in] Sb           Pointer to the superblock.
   @return The superblock's checksum.
**/
static bool ext4_verify_sb_csum(const ext4_superblock *sb)
{
    if (!EXT4_HAS_METADATA_CSUM(sb))
    {
        return true;
    }

    return sb->sb->s_checksum == ext4_calculate_sb_csum(sb);
}

void ext4_delete_inode(struct inode *inode_, uint32_t inum, struct ext4_superblock *fs)
{
    struct ext4_inode *inode = ext4_get_inode_from_node(inode_);

    inode->i_dtime = clock_get_posix_time();
    ext4_free_inode_space(inode_, fs);

    inode->i_links = 0;
    fs->update_inode(inode, inum);

    uint32_t block_group = (inum - 1) / fs->inodes_per_block_group;

    if (S_ISDIR(inode->i_mode))
        fs->block_groups[block_group].dec_used_dirs();

    fs->free_inode(inum);
}

void ext4_close(struct inode *vfs_ino)
{
    struct ext4_inode *inode = ext4_get_inode_from_node(vfs_ino);

    /* TODO: It would be better, cache-wise and memory allocator-wise if we
     * had ext4_inode incorporate a struct inode inside it, and have everything in the same
     * location.
     * TODO: We're also storing a lot of redudant info in ext4_inode(we already have most stuff in
     * the regular struct inode).
     */
    free(inode);
}

ssize_t ext4_writepage(page *page, size_t off, inode *ino)
{
    auto buf = block_buf_from_page(page);
    auto sb = ext4_superblock_from_inode(ino);

    assert(buf != nullptr);

    while (buf)
    {
        page_iov v[1];
        v->length = buf->block_size;
        v->page = buf->this_page;
        v->page_off = buf->page_off;

#if 0
		printk("Writing to block %lu\n", buf->block_nr);
#endif

        if (sb_write_bio(sb, v, 1, buf->block_nr) < 0)
        {
            sb->error("Error writing back page");
            return -EIO;
        }

        buf = buf->next;
    }

    return PAGE_SIZE;
}

ssize_t ext4_readpage(struct page *page, size_t off, struct inode *ino)
{
    bool is_buffer = page->flags & PAGE_FLAG_BUFFER;

    assert(is_buffer == true);

    auto e4ino = (ext4_inode_info *) ino;
    auto sb = ext4_superblock_from_inode(ino);
    auto nr_blocks = PAGE_SIZE / sb->block_size;
    auto base_block_index = off / sb->block_size;

    auto curr_off = 0;

    for (size_t i = 0; i < nr_blocks; i++)
    {
        struct block_buf *b = nullptr;
        if (is_buffer && !(b = page_add_blockbuf(page, curr_off)))
        {
            page_destroy_block_bufs(page);
            return -ENOMEM;
        }

        auto res = ext4_get_block_from_inode(e4ino, base_block_index + i, sb);
        if (res.has_error())
        {
            page_destroy_block_bufs(page);
            return res.error();
        }

        /* TODO: Coalesce reads */
        page_iov v[1];
        v->page = page;
        v->length = sb->block_size;
        v->page_off = curr_off;

        if (sb_read_bio(sb, v, 1, res.value()) < 0)
        {
            page_destroy_block_bufs(page);
            return -EIO;
        }

        if (is_buffer)
        {
            b->block_nr = res.value();
            b->block_size = sb->block_size;
            b->dev = sb->s_bdev;
        }

        curr_off += sb->block_size;
    }

    return min(PAGE_SIZE, ino->i_size - off);
}

inode *ext4_get_inode(ext4_superblock *sb, uint32_t inode_num)
{
    /* First we try to find the inode in the cache, if it's not there,
     * we unlock the lock and try and read it in. Then we retry to read
     * from the hashtable, and if it's there we free the one we read;
     * if not, we insert and return ours.
     */

    auto ino = superblock_find_inode(sb, inode_num);

    if (ino)
        return ino;

    inode_unlock_hashtable(sb, inode_num);

    ino = ext4_load_inode_from_disk(inode_num, sb);

    if (!ino)
        return nullptr;

    auto new_ = superblock_find_inode(sb, inode_num);

    if (new_)
    {
        free(ino->i_helper);
        delete ino;
        return new_;
    }

    superblock_add_inode_unlocked(sb, ino);

    return ino;
}

struct inode *ext4_open(struct dentry *dir, const char *name)
{
    struct inode *ino = dir->d_inode;
    struct ext4_superblock *fs = ext4_superblock_from_inode(ino);
    uint32_t inode_num;

    struct ext4_dirent_result res;
    int st = ext4_retrieve_dirent(ino, name, fs, &res);

    if (st < 0)
    {
        return errno = -st, nullptr;
    }

    ext4_dir_entry_t *dentry = (ext4_dir_entry_t *) (res.buf + res.block_off);

    inode_num = dentry->inode;

    free(res.buf);

    return ext4_get_inode(fs, inode_num);
}

struct inode *ext4_fs_ino_to_vfs_ino(struct ext4_inode *inode, uint32_t inumber,
                                     ext4_superblock *sb)
{
    bool has_vmo = S_ISDIR(inode->i_mode) || S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode);
    /* Create a file */
    struct ext4_inode_info *ino = new ext4_inode_info;

    if (!ino)
    {
        return nullptr;
    }

    if (inode_init(ino, has_vmo) < 0)
    {
        delete ino;
        return nullptr;
    }

    /* Possible when mounting the root inode */
    if (sb)
    {
        ino->i_dev = sb->s_devnr;
        ino->i_sb = sb;
    }

    ino->i_inode = inumber;
    /* Detect the file type */
    ino->i_type = ext4_ino_type_to_vfs_type(inode->i_mode);
    ino->i_mode = inode->i_mode;

    /* We're storing dev in dbp[0] in the same format as dev_t */
    ino->i_rdev = inode->i_data[0];

    ino->i_size = EXT4_CALCULATE_SIZE64(inode);
    if (has_vmo)
        ino->i_pages->size = ino->i_size;

    ino->i_uid = inode->i_uid;
    ino->i_gid = inode->i_gid;
    ino->i_atime = inode->i_atime;
    ino->i_ctime = inode->i_ctime;
    ino->i_mtime = inode->i_mtime;
    ino->i_nlink = inode->i_links;
    ino->i_blocks = inode->i_blocks;

    ino->raw_inode = inode;

    ino->i_fops = &ext4_ops;

    return ino;
}

uint16_t ext4_mode_to_ino_type(mode_t mode)
{
    if (S_ISFIFO(mode))
        return EXT4_INO_TYPE_FIFO;
    if (S_ISCHR(mode))
        return EXT4_INO_TYPE_CHARDEV;
    if (S_ISBLK(mode))
        return EXT4_INO_TYPE_BLOCKDEV;
    if (S_ISDIR(mode))
        return EXT4_INO_TYPE_DIR;
    if (S_ISLNK(mode))
        return EXT4_INO_TYPE_SYMLINK;
    if (S_ISSOCK(mode))
        return EXT4_INO_TYPE_UNIX_SOCK;
    if (S_ISREG(mode))
        return EXT4_INO_TYPE_REGFILE;
    return -1;
}

int ext4_ino_type_to_vfs_type(uint16_t mode)
{
    if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_DIR)
        return VFS_TYPE_DIR;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_REGFILE)
        return VFS_TYPE_FILE;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_BLOCKDEV)
        return VFS_TYPE_BLOCK_DEVICE;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_CHARDEV)
        return VFS_TYPE_CHAR_DEVICE;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_SYMLINK)
        return VFS_TYPE_SYMLINK;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_FIFO)
        return VFS_TYPE_FIFO;
    else if (EXT4_GET_FILE_TYPE(mode) == EXT4_INO_TYPE_UNIX_SOCK)
        return VFS_TYPE_UNIX_SOCK;

    return VFS_TYPE_UNK;
}

struct inode *ext4_create_file(const char *name, mode_t mode, dev_t dev, struct dentry *dir)
{
    struct inode *vfs_ino = dir->d_inode;
    struct ext4_superblock *fs = ext4_superblock_from_inode(vfs_ino);
    uint32_t inumber = 0;
    struct inode *ino = nullptr;

    auto res = fs->allocate_inode();
    if (res.has_error())
    {
        errno = -res.error();
        return nullptr;
    }

    auto p = res.value();
    inumber = p.first;

    struct ext4_inode *inode = p.second;
    struct ext4_inode *dir_inode = ext4_get_inode_from_node(vfs_ino);

    if (!inode)
        return nullptr;

    memset(inode, 0, sizeof(struct ext4_inode));
    inode->i_ctime = inode->i_atime = inode->i_mtime = (uint32_t) clock_get_posix_time();

    struct creds *c = creds_get();
    unsigned long old = 0;

    inode->i_uid = c->euid;
    inode->i_gid = c->egid;

    creds_put(c);

    inode->i_links = 1;
    uint16_t ext4_file_type = ext4_mode_to_ino_type(mode);
    if (ext4_file_type == (uint16_t) -1)
    {
        errno = EINVAL;
        goto free_ino_error;
    }

    inode->i_mode = ext4_file_type | (mode & ~S_IFMT);

    if (S_ISBLK(mode) || S_ISCHR(mode))
    {
        /* We're a device file, store the device in dbp[0] */
        inode->i_data[0] = dev;
    }

    fs->update_inode(inode, inumber);
    fs->update_inode(dir_inode, vfs_ino->i_inode);

    old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    if (int st = ext4_add_direntry(name, inumber, inode, vfs_ino, fs); st < 0)
    {
        thread_change_addr_limit(old);
        printk("ext4 error %d\n", st);
        errno = EINVAL;
        goto free_ino_error;
    }

    if (S_ISDIR(mode))
        inode_inc_nlink(vfs_ino);

    thread_change_addr_limit(old);

    ino = ext4_fs_ino_to_vfs_ino(inode, inumber, fs);
    if (!ino)
    {
        errno = ENOMEM;
        goto unlink_ino;
    }

    superblock_add_inode(vfs_ino->i_sb, ino);

    return ino;

unlink_ino:
    ext4_unlink(name, 0, dir);
    free(ino);
free_ino_error:
    free(inode);
    fs->free_inode(inumber);

    return nullptr;
}

struct inode *ext4_creat(const char *name, int mode, struct dentry *dir)
{
    unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    struct inode *i = ext4_create_file(name, (mode & ~S_IFMT) | S_IFREG, 0, dir);

    thread_change_addr_limit(old);

    return i;
}

int ext4_flush_inode(struct inode *inode)
{
    struct ext4_inode *ino = ext4_get_inode_from_node(inode);
    struct ext4_superblock *fs = ext4_superblock_from_inode(inode);

    /* Refresh the on-disk struct with the vfs inode data */
    ino->i_atime = inode->i_atime;
    ino->i_ctime = inode->i_ctime;
    ino->i_mtime = inode->i_mtime;
    ino->i_size_lo = (uint32_t) inode->i_size;
    ino->i_size_hi = (uint32_t) (inode->i_size >> 32);
    ino->i_gid = inode->i_gid;
    ino->i_uid = inode->i_uid;
    ino->i_links = (uint16_t) inode->i_nlink;
    ino->i_blocks = (uint32_t) inode->i_blocks;
    ino->i_mode = inode->i_mode;
    ino->i_uid = inode->i_uid;

    fs->update_inode(ino, (ext4_inode_no) inode->i_inode);

    return 0;
}

int ext4_kill_inode(struct inode *inode)
{
    struct ext4_superblock *fs = ext4_superblock_from_inode(inode);

    ext4_delete_inode(inode, (uint32_t) inode->i_inode, fs);
    return 0;
}

int ext4_statfs(struct statfs *buf, superblock *sb)
{
    return ((ext4_superblock *) sb)->stat_fs(buf);
}

const uint32_t ext4_supported_features_compat = EXT4_FEATURE_COMPAT_EXT_ATTR;

const uint32_t ext4_supported_featured_rocompat =
    EXT4_FEATURE_RO_COMPAT_DIR_NLINK | EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE |
    EXT4_FEATURE_RO_COMPAT_HUGE_FILE | EXT4_FEATURE_RO_COMPAT_LARGE_FILE |
    EXT4_FEATURE_RO_COMPAT_GDT_CSUM | EXT4_FEATURE_RO_COMPAT_METADATA_CSUM |
    EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER;

const uint32_t ext4_supported_features_incompat =
    EXT4_FEATURE_INCOMPAT_64BIT | EXT4_FEATURE_INCOMPAT_DIRDATA | EXT4_FEATURE_INCOMPAT_FLEX_BG |
    EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS;

struct inode *ext4_mount_partition(struct blockdev *dev)
{
    LOG("ext4", "mounting ext4 partition on block device %s\n", dev->name.c_str());
    ext4_superblock *sb = new ext4_superblock;
    if (!sb)
        return nullptr;

    struct inode *root_inode = nullptr;
    unsigned int block_size = 0;
    unsigned long superblock_block = 0;
    unsigned long sb_off = 0;
    unsigned long entries = 0;
    struct page *page;

    dev->sb = sb;

    sb->s_block_size = EXT4_SUPERBLOCK_OFFSET;
    sb->s_bdev = dev;

    struct block_buf *b = sb_read_block(sb, 1);

    superblock_t *ext4_sb = (superblock_t *) block_buf_data(b);

    if (ext4_sb->s_magic == EXT4_SIGNATURE)
        LOG("ext4", "valid ext4 signature detected!\n");
    else
    {
        ERROR("ext4", "invalid ext4 signature %x\n", ext4_sb->s_magic);
        errno = EINVAL;
        block_buf_put(b);
        goto error;
    }

    block_size = 1024 << ext4_sb->s_log_block_size;

    if (block_size > MAX_BLOCK_SIZE)
    {
        ERROR("ext4", "bad block size %u\n", block_size);
        block_buf_put(b);
        goto error;
    }

    /* Since we're re-adjusting the block buffer to be the actual block buffer,
     * we're deleting this block_buf and grabbing a new one
     */

    page = b->this_page;
    block_buf_free(b);
    page_destroy_block_bufs(page);
    b = nullptr;

    sb->s_block_size = block_size;
    superblock_block = block_size == 1024 ? 1 : 0;
    sb_off = EXT4_SUPERBLOCK_OFFSET & (block_size - 1);

    b = sb_read_block(sb, superblock_block);

    if (!b)
    {
        /* :( riperino the bufferino */
        goto error;
    }

    ext4_sb = (superblock_t *) ((char *) block_buf_data(b) + sb_off);

    if (ext4_sb->s_rev_level == EXT4_DYNAMIC_REV)
    {
        sb->features_compat = ext4_sb->s_feature_compat;
        sb->features_incompat = ext4_sb->s_feature_incompat;
        sb->features_ro_compat = ext4_sb->s_feature_ro_compat;
        sb->inode_size = ext4_sb->s_inode_size;
    }
    else if (ext4_sb->s_rev_level == EXT4_GOOD_OLD_REV)
    {
        sb->features_compat = 0;
        sb->features_incompat = 0;
        sb->features_ro_compat = 0;
        sb->inode_size = EXT4_GOOD_OLD_INODE_SIZE;
    }
    else
    {
        ERROR("ext4", "couldn't mount: Unknown revision level");
        goto error;
    }

    (void) ext4_supported_features_compat;

    if (sb->features_incompat & ~ext4_supported_features_incompat)
    {
        ERROR("ext4", "couldn't mount: Unsupported features %08x\n",
              sb->features_incompat & ~ext4_supported_features_incompat);
        goto error;
    }

    printk("Extents? %s\n", sb->features_incompat & EXT4_FEATURE_INCOMPAT_EXTENTS ? "yes" : "no");

    if (sb->features_ro_compat & ~ext4_supported_featured_rocompat)
    {
        INFO("ext4", "mounting read-only due to not understood rocompat %08x\n",
             sb->features_ro_compat & ~ext4_supported_featured_rocompat);
    }

    if (EXT4_IS_64_BIT(sb))
    {
        // s_desc_size should be 4 byte aligned and
        // 64 bit filesystems need DescSize to be 64 bytes
        if (((ext4_sb->s_desc_size % 4) != 0) ||
            (ext4_sb->s_desc_size < EXT4_64BIT_BLOCK_DESC_SIZE))
        {
            return nullptr;
        }

        sb->desc_size = ext4_sb->s_desc_size;
    }
    else
    {
        sb->desc_size = EXT4_OLD_BLOCK_DESC_SIZE;
    }

    sb->s_devnr = sb->s_bdev->dev->dev();
    sb->sb_bb = b;
    sb->sb = ext4_sb;
    sb->major = ext4_sb->s_rev_level;
    sb->minor = ext4_sb->s_minor_rev_level;
    sb->total_inodes = ext4_sb->s_inodes_count;
    sb->total_blocks = ext4_sb->s_blocks_count;
    sb->block_size = block_size;
    sb->block_size_shift = ilog2(block_size);
    sb->frag_size = 1024 << ext4_sb->s_log_frag_size;
    sb->inode_size = ext4_sb->s_inode_size;
    sb->blocks_per_block_group = ext4_sb->s_blocks_per_group;
    sb->inodes_per_block_group = ext4_sb->s_inodes_per_group;
    sb->number_of_block_groups = sb->total_blocks / sb->blocks_per_block_group;
    entries = sb->block_size / sizeof(uint32_t);
    sb->entry_shift = ilog2(entries);

    if (!ext4_verify_sb_csum(sb))
    {
        printf("ext4: Filesystem on %s with bad superblock checksum\n", dev->name.c_str());
        return errno = EIO, nullptr;
    }

    if (sb->total_blocks % sb->blocks_per_block_group)
        sb->number_of_block_groups++;

    if (sb->features_incompat & EXT4_FEATURE_INCOMPAT_CSUM_SEED)
    {
        sb->initial_seed = ext4_sb->s_checksum_seed;
    }
    else
    {
        sb->initial_seed = ext4_calculate_csum(sb, (void *) ext4_sb->s_uuid, 16, ~0U);
    }

    for (unsigned int i = 0; i < sb->number_of_block_groups; i++)
    {
        ext4_block_group bg{i, sb};
        if (int st = bg.init(); st < 0)
        {
            errno = -st;
            goto error;
        }

        if (!sb->block_groups.push_back(cul::move(bg)))
            goto error;
    }

    root_inode = ext4_load_inode_from_disk(2, sb);
    if (!root_inode)
        goto error;

    superblock_add_inode(sb, root_inode);
    sb->flush_inode = ext4_flush_inode;
    sb->kill_inode = ext4_kill_inode;
    sb->statfs = ext4_statfs;

    sb->sb->s_mtime = clock_get_posix_time();
    sb->sb->s_mnt_count++;

    block_buf_dirty(sb->sb_bb);

    root_inode->i_fops = &ext4_ops;

    return root_inode;
error:
    if (b)
        block_buf_put(b);
    delete sb;

    return nullptr;
}

__init void init_ext4drv()
{
    if (fs_mount_add(ext4_mount_partition, 0, "ext4") < 0)
        FATAL("ext4", "error initializing the fs mount data\n");
}

off_t ext4_getdirent(struct dirent *buf, off_t off, struct file *f)
{
    off_t new_off;
    ext4_dir_entry_t entry;
    ssize_t read;

    unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    /* Read a dir entry from the offset */
    read = file_read_cache(&entry, sizeof(ext4_dir_entry_t), f->f_ino, off);
    thread_change_addr_limit(old);
    if (read < 0)
        return read;

    /* If we reached the end of the directory buffer, return 0 */
    if (read == 0)
        return 0;

    /* If we reached the end of the directory list, return 0 */
    if (!entry.inode)
        return 0;

    memcpy(buf->d_name, entry.name, entry.name_len);
    buf->d_name[entry.name_len] = '\0';
    buf->d_ino = entry.inode;
    buf->d_off = off;
    buf->d_reclen = sizeof(struct dirent) - (256 - (entry.name_len + 1));
    buf->d_type = entry.file_type;

    new_off = off + entry.rec_len;

    return new_off;
}

struct inode *ext4_mknod(const char *name, mode_t mode, dev_t dev, struct dentry *dir)
{
    return ext4_create_file(name, mode, dev, dir);
}

struct inode *ext4_mkdir(const char *name, mode_t mode, struct dentry *dir)
{
    struct inode *new_dir = ext4_create_file(name, (mode & 0777) | S_IFDIR, 0, dir);
    if (!new_dir)
    {
        return nullptr;
    }

    new_dir->i_nlink = 2;

    /* Create the two basic links - link to self and link to parent */
    /* FIXME: Handle failure here? */
    ext4_link(new_dir, ".", new_dir);
    ext4_link(dir->d_inode, "..", new_dir);

    struct ext4_superblock *fs = ext4_superblock_from_inode(dir->d_inode);

    uint32_t inum = (uint32_t) new_dir->i_inode;

    fs->block_groups[ext4_inode_number_to_bg(inum, fs)].inc_used_dirs();

    inode_mark_dirty(new_dir);

    return new_dir;
}

/**
 * @brief Reports a filesystem error
 *
 * @param str Error Message
 */
void ext4_superblock::error(const char *str, ...) const
{
    char *buf = (char *) malloc(512);
    bool stack = false;
    if (!buf)
    {
        // Cheers, I hate this. But lets prioritize error reporting
        stack = true;
        buf = (char *) alloca(200);
    }

    va_list va;
    va_start(va, str);
    int st = vsnprintf(buf, stack ? 200 : 512, str, va);

    if (st < 0)
        strcpy(buf, "<bad error format string>");

    va_end(va);
    printk("ext4 error: %s\n", buf);

    if (!stack)
        free(buf);

    sb->s_state = EXT4_ERROR_FS;
    block_buf_dirty(sb_bb);
    block_buf_writeback(sb_bb);

    if (sb->s_errors == EXT4_ERRORS_CONTINUE)
        return;
    else if (sb->s_errors == EXT4_ERRORS_PANIC)
        panic("ext4: Panic from previous filesystem error");

    /* TODO: Add (re)mouting read-only */
}

/**
 * @brief Does statfs
 *
 * @param buf statfs struct to fill
 * @return 0 on success, negative error codes (in our case, always succesful)
 */
int ext4_superblock::stat_fs(struct statfs *buf)
{
    buf->f_type = EXT4_SIGNATURE;
    buf->f_bsize = block_size;
    buf->f_blocks = sb->s_blocks_count;
    buf->f_bfree = sb->s_free_blocks_count;
    buf->f_bavail = sb->s_free_blocks_count - sb->s_r_blocks_count;
    buf->f_files = sb->s_inodes_count;
    buf->f_ffree = sb->s_free_inodes_count;

    return 0;
}

/**
   Calculates the checksum of the given buffer.
   @param[in]      Partition     Pointer to the opened EXT4 partition.
   @param[in]      Buffer        Pointer to the buffer.
   @param[in]      Length        Length of the buffer, in bytes.
   @param[in]      InitialValue  Initial value of the CRC.
   @return The checksum.
**/
uint32_t ext4_calculate_csum(const ext4_superblock *sb, const void *buffer, size_t length,
                             uint32_t initial_value)
{
    if (!EXT4_HAS_METADATA_CSUM(sb))
    {
        return 0;
    }

    switch (sb->sb->s_checksum_type)
    {
        case EXT4_CHECKSUM_CRC32C:
            // For some reason, EXT4 really likes non-inverted CRC32C checksums, so we stick to that
            // here.
            return ~crc32c_calculate(buffer, length, ~initial_value);
        default:
            panic("ext4: Bad checksum type %u - this should be unreachable\n",
                  sb->sb->s_checksum_type);
            return 0;
    }
}
