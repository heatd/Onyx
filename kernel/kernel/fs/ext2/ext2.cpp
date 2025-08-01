/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ext2.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/block.h>
#include <onyx/buffer.h>
#include <onyx/compiler.h>
#include <onyx/cred.h>
#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/filemap.h>
#include <onyx/fs_mount.h>
#include <onyx/limits.h>
#include <onyx/log.h>
#include <onyx/pagecache.h>
#include <onyx/panic.h>
#include <onyx/types.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include <uapi/dirent.h>
#include <uapi/fs.h>

int ext2_open(struct dentry *dir, const char *name, struct dentry *dentry);
off_t ext2_getdirent(struct dirent *buf, off_t off, struct file *f);
struct inode *ext2_creat(struct dentry *dentry, int mode, struct dentry *dir);
char *ext2_readlink(struct dentry *dentry);
void ext2_free_inode(struct inode *ino);
struct inode *ext2_mknod(struct dentry *dentry, mode_t mode, dev_t dev, struct dentry *dir);
struct inode *ext2_mkdir(struct dentry *dentry, mode_t mode, struct dentry *dir);
int ext2_link_fops(struct dentry *old_dentry, struct dentry *new_dentry);
int ext2_fallocate(int mode, off_t off, off_t len, struct file *f);
int ext2_ftruncate(size_t len, struct file *f);
ssize_t ext2_readpage(struct page *page, size_t off, struct inode *ino);
static ssize_t ext2_writepage(struct vm_object *obj, page *page, size_t off);
int ext2_prepare_write(inode *ino, struct page *page, size_t page_off, size_t offset, size_t len);
int ext2_link(struct inode *target, const char *name, struct inode *dir);
inode *ext2_symlink(struct dentry *dentry, const char *dest, struct dentry *dir);
static int ext2_fsyncdata(struct inode *ino, struct writepages_info *wpinfo);
static int ext2_readpages(struct readpages_state *state, struct inode *ino);
static unsigned int ext2_ioctl(int request, void *argp, struct file *file);
int ext2_rename(struct dentry *src_parent, struct dentry *src, struct dentry *dst_dir,
                struct dentry *dst);

struct file_ops ext2_ops = {
    .getdirent = ext2_getdirent,
    .ioctl = ext2_ioctl,
    .fallocate = ext2_fallocate,
    .read_iter = filemap_read_iter,
    .write_iter = filemap_write_iter,
    .fsyncdata = ext2_fsyncdata,
};

const struct inode_operations ext2_ino_ops = {
    .open = ext2_open,
    .creat = ext2_creat,
    .rename = ext2_rename,
    .link = ext2_link_fops,
    .ftruncate = ext2_ftruncate,
    .mkdir = ext2_mkdir,
    .mknod = ext2_mknod,
    .symlink = ext2_symlink,
    .readlink = ext2_readlink,
    .unlink = ext2_unlink,
};

void ext2_delete_inode(struct inode *inode_, uint32_t inum, struct ext2_superblock *fs)
{
    struct ext2_inode *inode = ext2_get_inode_from_node(inode_);

    inode->i_dtime = clock_get_posix_time();
    ext2_free_inode_space(inode_, fs);

    inode->i_links = 0;
    fs->update_inode(inode, inum);

    uint32_t block_group = (inum - 1) / fs->inodes_per_block_group;

    if (S_ISDIR(inode->i_mode))
        fs->block_groups[block_group].dec_used_dirs();

    fs->free_inode(inum);
}

void ext2_free_inode(struct inode *vfs_ino)
{
    struct ext2_inode *inode = ext2_get_inode_from_node(vfs_ino);

    /* TODO: It would be better, cache-wise and memory allocator-wise if we
     * had ext2_inode incorporate a struct inode inside it, and have everything in the same
     * location.
     * TODO: We're also storing a lot of redudant info in ext2_inode(we already have most stuff in
     * the regular struct inode).
     */
    free(inode);
}

static void ext2_writepage_endio(struct bio_req *req)
{
    struct page *page = req->vec[0].page;
    struct block_buf *buf = (struct block_buf *) req->b_private;
    struct block_buf *head = (struct block_buf *) page->priv;
    DCHECK(head != nullptr);

    spin_lock(&head->pagestate_lock);
    bb_clear_flag(buf, BLOCKBUF_FLAG_WRITEBACK);
    if (!page_has_writeback_bufs(page))
        page_end_writeback(page);
    spin_unlock(&head->pagestate_lock);
}

static ssize_t ext2_writepage(struct vm_object *obj, page *page, size_t off) REQUIRES(page)
    RELEASE(page)
{
    auto buf = block_buf_from_page(page);
    struct inode *ino = obj->ino;
    auto sb = ext2_superblock_from_inode(ino);
    unsigned int nr_ios = 0;
    DCHECK(buf != nullptr);

    page_start_writeback(page);

    while (buf)
    {
        page_iov v[1];
        v->length = buf->block_size;
        v->page = buf->this_page;
        DCHECK(buf->this_page == page);
        v->page_off = buf->page_off;
        if (buf->block_nr == EXT2_FILE_HOLE_BLOCK)
        {
            buf = buf->next;
            continue;
        }

        buf->flags |= BLOCKBUF_FLAG_WRITEBACK;

#if 0
		printk("Writing to block %lu\n", buf->block_nr);
#endif

        if (sb_write_bio(sb, v, 1, buf->block_nr, ext2_writepage_endio, buf) < 0)
        {
            page_end_writeback(page);
            sb->error("Error writing back page");
            unlock_page(page);
            return -EIO;
        }

        nr_ios++;
        buf = buf->next;
    }

    /* For this to have been a valid dirty page, we must've been able to submit more than 0 ios (a
     * page full of zero blocks cannot be dirty, as prepare_write must be called). */
    CHECK_PAGE(nr_ios > 0, page);
    unlock_page(page);

    return PAGE_SIZE;
}

int ext2_map_page(struct page *page, size_t off, struct inode *ino)
{
    auto raw_inode = ext2_get_inode_from_node(ino);
    auto sb = ext2_superblock_from_inode(ino);
    auto nr_blocks = PAGE_SIZE / sb->block_size;
    auto base_block_index = off / sb->block_size;
    int curr_off = 0;
    bool all_holes = true;

    if (!page_test_set_flag(page, PAGE_FLAG_BUFFER))
        return 0;

    for (size_t i = 0; i < nr_blocks; i++)
    {
        struct block_buf *b = nullptr;
        if (!(b = page_add_blockbuf(page, curr_off)))
        {
            page_destroy_block_bufs(page);
            __atomic_and_fetch(&page->flags, ~PAGE_FLAG_BUFFER, __ATOMIC_RELEASE);
            return -ENOMEM;
        }

        auto res = ext2_get_block_from_inode(raw_inode, base_block_index + i, sb);
        if (res.has_error())
        {
            page_destroy_block_bufs(page);
            __atomic_and_fetch(&page->flags, ~PAGE_FLAG_BUFFER, __ATOMIC_RELEASE);
            return -ENOMEM;
        }

        auto block = res.value();
        if (block == EXT2_ERR_INV_BLOCK)
        {
            // Zero the block, since it's a hole
            page_zero_range(page, b->page_off, sb->block_size);
            bb_test_and_set(b, BLOCKBUF_FLAG_UPTODATE);
        }
        else
            all_holes = false;

        b->block_nr = res.value();
        b->block_size = sb->block_size;
        b->dev = sb->s_bdev;

        curr_off += sb->block_size;
    }

    if (all_holes)
        page_test_set_flag(page, PAGE_FLAG_UPTODATE);

    return 0;
}

ssize_t ext2_readpage(struct page *page, size_t off, struct inode *ino)
{
    auto sb = ext2_superblock_from_inode(ino);
    auto curr_off = 0;

    if (int st = ext2_map_page(page, off, ino); st < 0)
        return st;

    for (struct block_buf *b = (struct block_buf *) page->priv; b != nullptr; b = b->next)
    {
        sector_t block = b->block_nr;
        if (bb_test_flag(b, BLOCKBUF_FLAG_UPTODATE))
            continue;

        if (block != EXT2_ERR_INV_BLOCK)
        {
            /* TODO: Coalesce reads */
            page_iov v[1];
            v->page = page;
            v->length = sb->block_size;
            v->page_off = curr_off;

            if (sb_read_bio(sb, v, 1, block) < 0)
                return -EIO;
        }

        bb_test_and_set(b, BLOCKBUF_FLAG_UPTODATE);
        curr_off += sb->block_size;
    }

    page_test_set_flag(page, PAGE_FLAG_UPTODATE);
    return min(PAGE_SIZE, ino->i_size - off);
}

void ext2_readpages_endio(struct bio_req *bio) NO_THREAD_SAFETY_ANALYSIS
{
    for (size_t i = 0; i < bio->nr_vecs; i++)
    {
        struct page_iov *iov = &bio->vec[i];
        DCHECK(page_locked(iov->page));
        struct block_buf *head = (struct block_buf *) iov->page->priv;

        spin_lock(&head->pagestate_lock);
        bool uptodate = true;

        for (struct block_buf *b = head; b != nullptr; b = b->next)
        {
            if (b->page_off == iov->page_off)
            {
                bb_clear_flag(b, BLOCKBUF_FLAG_AREAD);
                CHECK(bb_test_and_set(b, BLOCKBUF_FLAG_UPTODATE));
                continue;
            }

            if (bb_test_flag(b, BLOCKBUF_FLAG_AREAD))
                uptodate = false;
        }

        spin_unlock(&head->pagestate_lock);

        if (uptodate)
        {
            if ((bio->flags & BIO_STATUS_MASK) == BIO_REQ_DONE)
                page_test_set_flag(iov->page, PAGE_FLAG_UPTODATE);
            unlock_page(iov->page);
        }
    }
}

static int ext2_readpages(struct readpages_state *state,
                          struct inode *ino) NO_THREAD_SAFETY_ANALYSIS
{
    auto sb = ext2_superblock_from_inode(ino);
    int st;
    struct page *page;
    unsigned int nr_ios = 0;

    while ((page = readpages_next_page(state)))
    {
        const unsigned long pgoff = page->pageoff;

        if (st = ext2_map_page(page, pgoff << PAGE_SHIFT, ino); st < 0)
            goto out_err;

        DCHECK(page->priv != 0);
        nr_ios = 0;

        for (struct block_buf *b = (struct block_buf *) page->priv; b != nullptr; b = b->next)
        {
            sector_t block = b->block_nr;
            if (block == 0)
                continue;
            if (bb_test_flag(b, BLOCKBUF_FLAG_UPTODATE))
                continue;
            if (!bb_test_and_set(b, BLOCKBUF_FLAG_AREAD))
                continue;
            DCHECK(!bb_test_flag(b, BLOCKBUF_FLAG_UPTODATE));

            struct bio_req *bio = bio_alloc(GFP_NOFS, 1);
            if (!bio)
            {
                bb_clear_flag(b, BLOCKBUF_FLAG_AREAD);
                st = -ENOMEM;
                goto out_err;
            }

            /* Note: We do not need to ref, we hold the lock, no one can throw this page away
             * while locked (almost like an implicit reference). */
            bio->sector_number = block * (sb->s_block_size / sb->s_bdev->sector_size);
            bio->flags = BIO_REQ_READ_OP;
            bio->b_end_io = ext2_readpages_endio;
            bio_push_pages(bio, page, b->page_off, b->block_size);
            st = bio_submit_request(sb->s_bdev, bio);
            bio_put(bio);

            if (st < 0)
            {
                bb_clear_flag(b, BLOCKBUF_FLAG_AREAD);
                goto out_err;
            }

            nr_ios++;
        }

        if (nr_ios == 0)
            unlock_page(page);
        page_unref(page);
    }

    return 0;
out_err:
    /* On error, release the page we're holding. We do not unlock it if we submitted any IOs for the
     * page, the endio page will do it for us. */
    if (nr_ios == 0)
        unlock_page(page);
    page_unref(page);
    return st;
}

struct ext2_inode_info *ext2_cache_inode_info(struct inode *ino, struct ext2_inode *fs_ino)
{
    struct ext2_inode_info *inf = new ext2_inode_info;
    if (!inf)
        return nullptr;

    inf->inode = fs_ino;

    return inf;
}

inode *ext2_get_inode(ext2_superblock *sb, uint32_t inode_num)
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

    ino = ext2_load_inode_from_disk(inode_num, sb);

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

int ext2_open(struct dentry *dir, const char *name, struct dentry *dentry)
{
    struct inode *ino = dir->d_inode;
    struct ext2_superblock *fs = ext2_superblock_from_inode(ino);
    uint32_t inode_num;

    struct ext2_dirent_result res;
    int st = ext2_retrieve_dirent(ino, name, fs, &res);

    if (st < 0)
        return st;

    ext2_dir_entry_t *dirent = (ext2_dir_entry_t *) (res.buf + res.block_off);
    inode_num = dirent->inode;
    free(res.buf);

    struct inode *inode = ext2_get_inode(fs, inode_num);
    if (!inode)
        return -errno;
    d_finish_lookup(dentry, inode);
    return 0;
}

void ext2_truncate_partial(struct vm_object *vmobj, struct page *page, size_t offset, size_t len);

static const struct vm_object_ops ext2_vm_obj_ops = {
    .free_page = buffer_free_page,
    .truncate_partial = ext2_truncate_partial,
    .writepage = ext2_writepage,
    .writepages = filemap_writepages,
    .readpages = ext2_readpages,
    .readpage = ext2_readpage,
    .prepare_write = ext2_prepare_write,
};

struct inode *ext2_fs_ino_to_vfs_ino(struct ext2_inode *inode, uint32_t inumber,
                                     ext2_superblock *sb)
{
    bool has_vmo = S_ISDIR(inode->i_mode) || S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode) ||
                   S_ISFIFO(inode->i_mode);
    /* Create a file */
    struct inode *ino = inode_create(has_vmo);

    if (!ino)
        return nullptr;

    /* Possible when mounting the root inode */
    if (sb)
    {
        ino->i_dev = sb->s_devnr;
        ino->i_sb = sb;
    }

    ino->i_inode = inumber;
    /* Detect the file type */
    ino->i_mode = inode->i_mode;

    /* We're storing dev in dbp[0] in the same format as dev_t */
    ino->i_rdev = inode->i_data[0];

    ino->i_size = EXT2_CALCULATE_SIZE64(inode);
    if (has_vmo)
    {
        ino->i_pages->size = ino->i_size;
        ino->i_pages->ops = &ext2_vm_obj_ops;
    }

    ino->i_uid = inode->i_uid;
    ino->i_gid = inode->i_gid;
    ino->i_atime = inode->i_atime;
    ino->i_ctime = inode->i_ctime;
    ino->i_mtime = inode->i_mtime;
    ino->i_nlink = inode->i_links;
    ino->i_blocks = inode->i_blocks;

    ino->i_helper = ext2_cache_inode_info(ino, inode);

    if (!ino->i_helper)
    {
        free(ino);
        return nullptr;
    }

    ino->i_fops = &ext2_ops;
    ino->i_op = &ext2_ino_ops;

    if (inode_is_special(ino))
    {
        int st = inode_special_init(ino);

        if (st < 0)
        {
            errno = -st;
            free(ino->i_helper);
            free(ino);
            return nullptr;
        }
    }

    return ino;
}

uint16_t ext2_mode_to_ino_type(mode_t mode)
{
    if (S_ISFIFO(mode))
        return EXT2_INO_TYPE_FIFO;
    if (S_ISCHR(mode))
        return EXT2_INO_TYPE_CHARDEV;
    if (S_ISBLK(mode))
        return EXT2_INO_TYPE_BLOCKDEV;
    if (S_ISDIR(mode))
        return EXT2_INO_TYPE_DIR;
    if (S_ISLNK(mode))
        return EXT2_INO_TYPE_SYMLINK;
    if (S_ISSOCK(mode))
        return EXT2_INO_TYPE_UNIX_SOCK;
    if (S_ISREG(mode))
        return EXT2_INO_TYPE_REGFILE;
    return -1;
}

struct inode *ext2_create_file(const char *name, mode_t mode, dev_t dev, struct dentry *dir)
{
    struct inode *vfs_ino = dir->d_inode;
    struct ext2_superblock *fs = ext2_superblock_from_inode(vfs_ino);
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

    struct ext2_inode *inode = p.second;
    struct ext2_inode *dir_inode = ext2_get_inode_from_node(vfs_ino);

    if (!inode)
        return nullptr;

    memset(inode, 0, sizeof(struct ext2_inode));
    inode->i_ctime = inode->i_atime = inode->i_mtime = (uint32_t) clock_get_posix_time();

    struct creds *c = creds_get();
    unsigned long old = 0;

    inode->i_uid = c->euid;
    inode->i_gid = c->egid;

    creds_put(c);

    inode->i_links = 1;
    uint16_t ext2_file_type = ext2_mode_to_ino_type(mode);
    if (ext2_file_type == (uint16_t) -1)
    {
        errno = EINVAL;
        goto free_ino_error;
    }

    inode->i_mode = ext2_file_type | (mode & ~S_IFMT);

    if (S_ISBLK(mode) || S_ISCHR(mode))
    {
        /* We're a device file, store the device in dbp[0] */
        inode->i_data[0] = dev;
    }

    fs->update_inode(inode, inumber);
    fs->update_inode(dir_inode, vfs_ino->i_inode);

    old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    if (int st = ext2_add_direntry(name, inumber, inode, vfs_ino, fs); st < 0)
    {
        thread_change_addr_limit(old);
        errno = -st;
        goto free_ino_error;
    }

    if (S_ISDIR(mode))
        inode_inc_nlink(vfs_ino);

    thread_change_addr_limit(old);

    ino = ext2_fs_ino_to_vfs_ino(inode, inumber, fs);
    if (!ino)
    {
        errno = ENOMEM;
        goto unlink_ino;
    }

    superblock_add_inode(vfs_ino->i_sb, ino);

    return ino;

unlink_ino:
    ext2_unlink(name, 0, dir);
    free(ino);
free_ino_error:
    free(inode);
    fs->free_inode(inumber);

    return nullptr;
}

struct inode *ext2_creat(struct dentry *dentry, int mode, struct dentry *dir)
{
    unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    struct inode *i = ext2_create_file(dentry->d_name, (mode & ~S_IFMT) | S_IFREG, 0, dir);

    thread_change_addr_limit(old);

    return i;
}

int ext2_flush_inode(struct inode *inode, bool in_sync)
{
    struct ext2_inode *ino = ext2_get_inode_from_node(inode);
    struct ext2_superblock *fs = ext2_superblock_from_inode(inode);

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

    fs->update_inode(ino, (ext2_inode_no) inode->i_inode, in_sync);

    return 0;
}

void ext2_evict_inode(struct inode *inode)
{
    struct ext2_superblock *fs = ext2_superblock_from_inode(inode);

    if (inode_get_nlink(inode) == 0)
        ext2_delete_inode(inode, (uint32_t) inode->i_inode, fs);
    else
        ext2_flush_inode(inode, false);
}

int ext2_statfs(struct statfs *buf, superblock *sb)
{
    return ((ext2_superblock *) sb)->stat_fs(buf);
}

static int ext2_shutdown_sb(struct superblock *sb_)
{
    ext2_superblock *sb = (ext2_superblock *) sb_;
    /* Shutdown the sb generically first, then tear down the ext2_superblock. This is required for
     * e.g sync purposes. */
    sb_generic_shutdown(sb);
    sb->~ext2_superblock();
    return 0;
}

static const struct super_ops ext2_sb_ops = {
    .flush_inode = ext2_flush_inode,
    .evict_inode = ext2_evict_inode,
    .statfs = ext2_statfs,
    .shutdown = ext2_shutdown_sb,
    .free_inode = ext2_free_inode,
};

struct superblock *ext2_mount_partition(struct vfs_mount_info *info)
{
    struct blockdev *dev = info->bdev;
    int err = -ENOMEM;
    struct inode *root_inode = nullptr;
    unsigned int block_size = 0;
    unsigned long superblock_block = 0;
    unsigned long sb_off = 0;
    unsigned long entries = 0;
    struct block_buf *b = nullptr;
    superblock_t *ext2_sb = nullptr;

    pr_info("ext2: mounting ext2 partition on block device %s\n", dev->name.c_str());
    ext2_superblock *sb = new ext2_superblock;
    if (!sb)
        goto error;

    dev->sb = sb;
    err = -EIO;
    if (block_set_bsize(dev, EXT2_SUPERBLOCK_OFFSET) < 0)
        goto error;
    sb->s_block_size = EXT2_SUPERBLOCK_OFFSET;
    sb->s_bdev = dev;

    b = sb_read_block(sb, 1);
    if (!b)
        goto error;

    ext2_sb = (superblock_t *) block_buf_data(b);

    if (ext2_sb->s_magic == EXT2_SIGNATURE)
        pr_info("ext2: valid ext2 signature detected!\n");
    else
    {
        pr_err("ext2: invalid ext2 signature %x\n", ext2_sb->s_magic);
        err = EINVAL;
        goto error;
    }

    block_size = 1024 << ext2_sb->s_log_block_size;

    if (block_size > MAX_BLOCK_SIZE)
    {
        pr_err("ext2: bad block size %u\n", block_size);
        err = -EINVAL;
        goto error;
    }

    block_buf_put(b);
    b = nullptr;

    if (block_set_bsize(dev, block_size) < 0)
        goto error;
    sb->s_block_size = block_size;

    superblock_block = block_size == 1024 ? 1 : 0;
    sb_off = EXT2_SUPERBLOCK_OFFSET & (block_size - 1);

    b = sb_read_block(sb, superblock_block);

    if (!b)
    {
        /* :( riperino the bufferino */
        goto error;
    }

    ext2_sb = (superblock_t *) ((char *) block_buf_data(b) + sb_off);

    if (ext2_sb->s_rev_level == EXT2_DYNAMIC_REV)
    {
        sb->features_compat = ext2_sb->s_feature_compat;
        sb->features_incompat = ext2_sb->s_feature_incompat;
        sb->features_ro_compat = ext2_sb->s_feature_ro_compat;
        sb->inode_size = ext2_sb->s_inode_size;
    }
    else if (ext2_sb->s_rev_level == EXT2_GOOD_OLD_REV)
    {
        sb->features_compat = 0;
        sb->features_incompat = 0;
        sb->features_ro_compat = 0;
        sb->inode_size = EXT2_GOOD_OLD_INODE_SIZE;
    }
    else
    {
        pr_err("ext2: couldn't mount: Unknown revision level\n");
        goto error;
    }

    sb->s_devnr = sb->s_bdev->dev->dev();
    sb->sb_bb = b;
    sb->sb = ext2_sb;
    sb->major = ext2_sb->s_rev_level;
    sb->minor = ext2_sb->s_minor_rev_level;
    sb->total_inodes = ext2_sb->s_inodes_count;
    sb->total_blocks = ext2_sb->s_blocks_count;
    sb->block_size = block_size;
    sb->block_size_shift = ilog2(block_size);
    sb->frag_size = 1024 << ext2_sb->s_log_frag_size;
    sb->inode_size = ext2_sb->s_inode_size;
    sb->blocks_per_block_group = ext2_sb->s_blocks_per_group;
    sb->inodes_per_block_group = ext2_sb->s_inodes_per_group;
    sb->number_of_block_groups = sb->total_blocks / sb->blocks_per_block_group;
    entries = sb->block_size / sizeof(uint32_t);
    sb->entry_shift = ilog2(entries);

    if (sb->total_blocks % sb->blocks_per_block_group)
        sb->number_of_block_groups++;

    for (unsigned int i = 0; i < sb->number_of_block_groups; i++)
    {
        ext2_block_group bg{i};
        if (!bg.init(sb))
            goto error;

        if (!sb->block_groups.push_back(cul::move(bg)))
            goto error;
    }

    root_inode = ext2_load_inode_from_disk(2, sb);
    if (!root_inode)
        goto error;

    superblock_add_inode(sb, root_inode);
    sb->s_ops = &ext2_sb_ops;

    sb->sb->s_mtime = clock_get_posix_time();
    sb->sb->s_mnt_count++;

    block_buf_dirty(sb->sb_bb);

    root_inode->i_fops = &ext2_ops;
    root_inode->i_op = &ext2_ino_ops;

    d_positiveize(info->root_dir, root_inode);
    return sb;
error:
    if (b)
        block_buf_put(b);
    delete sb;

    return (struct superblock *) ERR_PTR(err);
}

__init void init_ext2drv()
{
    if (fs_mount_add(ext2_mount_partition, 0, "ext2") < 0)
        FATAL("ext2", "error initializing the fs mount data\n");
}

#define EXT2_FT_UNKNOWN 0
#define EXT2_FT_REG     1
#define EXT2_FT_DIR     2
#define EXT2_FT_CHRDEV  3
#define EXT2_FT_BLKDEV  4
#define EXT2_FT_FIFO    5
#define EXT2_FT_SOCK    6
#define EXT2_FT_SYMLINK 7
#define EXT2_FT_MAX     8

static const u8 ft_to_dt_table[] = {
    DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK,
};

off_t ext2_getdirent(struct dirent *buf, off_t off, struct file *f)
{
    off_t new_off;
    ext2_dir_entry_t entry;
    ssize_t read;

retry:
    unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    /* Read a dir entry from the offset */
    read = file_read_cache(&entry, sizeof(ext2_dir_entry_t), f->f_ino, off);
    if (read < 0)
        return read;

    thread_change_addr_limit(old);

    /* If we reached the end of the directory buffer, return 0 */
    if (read == 0)
        return 0;

    /* Should ignore this entry, increment off and retry */
    if (!entry.inode)
    {
        off += entry.rec_len;
        goto retry;
    }

    memcpy(buf->d_name, entry.name, entry.name_len);
    buf->d_name[entry.name_len] = '\0';
    buf->d_ino = entry.inode;
    buf->d_off = off;
    buf->d_reclen = sizeof(struct dirent) - (256 - (entry.name_len + 1));
    buf->d_type = entry.file_type >= EXT2_FT_MAX ? DT_UNKNOWN : ft_to_dt_table[entry.file_type];

    new_off = off + entry.rec_len;

    return new_off;
}

struct inode *ext2_mknod(struct dentry *dentry, mode_t mode, dev_t dev, struct dentry *dir)
{
    return ext2_create_file(dentry->d_name, mode, dev, dir);
}

struct inode *ext2_mkdir(struct dentry *dentry, mode_t mode, struct dentry *dir)
{
    struct inode *new_dir = ext2_create_file(dentry->d_name, (mode & 0777) | S_IFDIR, 0, dir);
    if (!new_dir)
        return nullptr;

    new_dir->i_nlink = 2;

    /* Create the two basic links - link to self and link to parent */
    /* FIXME: Handle failure here? */
    ext2_link(new_dir, ".", new_dir);
    ext2_link(dir->d_inode, "..", new_dir);

    struct ext2_superblock *fs = ext2_superblock_from_inode(dir->d_inode);

    uint32_t inum = (uint32_t) new_dir->i_inode;

    fs->block_groups[ext2_inode_number_to_bg(inum, fs)].inc_used_dirs();

    inode_mark_dirty(new_dir);

    return new_dir;
}

/**
 * @brief Reports a filesystem error
 *
 * @param str Error Message
 */
void ext2_superblock::error(const char *str) const
{
    pr_err("ext2_error: %s\n", str);

    sb->s_state = EXT2_ERROR_FS;
    block_buf_dirty(sb_bb);
    block_buf_sync(sb_bb);

    if (sb->s_errors == EXT2_ERRORS_CONTINUE)
        return;
    else if (sb->s_errors == EXT2_ERRORS_PANIC)
        panic("ext2: Panic from previous filesystem error");

    /* TODO: Add (re)mouting read-only */
}

/**
 * @brief Does statfs
 *
 * @param buf statfs struct to fill
 * @return 0 on success, negative error codes (in our case, always succesful)
 */
int ext2_superblock::stat_fs(struct statfs *buf)
{
    buf->f_type = EXT2_SIGNATURE;
    buf->f_bsize = block_size;
    buf->f_blocks = sb->s_blocks_count;
    buf->f_bfree = sb->s_free_blocks_count;
    buf->f_bavail = sb->s_free_blocks_count - sb->s_r_blocks_count;
    buf->f_files = sb->s_inodes_count;
    buf->f_ffree = sb->s_free_inodes_count;

    return 0;
}

static int ext2_fsyncdata(struct inode *ino, struct writepages_info *wpinfo)
{
    /* Sync the actual pages, then writeback indirect blocks */
    if (int st = filemap_writepages(ino, wpinfo); st < 0)
        return st;
    /* If not a block device, sync indirect blocks (that have been associated with the vm
     * object) */
    if (!S_ISBLK(ino->i_mode))
        block_buf_sync_assoc(ino->i_pages);
    return 0;
}

static int ext2_do_bmap_from_page_cache(struct file *file, unsigned int logical_block,
                                        unsigned int *ret) NO_THREAD_SAFETY_ANALYSIS
{
    struct inode *ino = file->f_ino;
    const ext2_superblock *sb = ext2_superblock_from_inode(ino);
    const unsigned int blocks_per_page = PAGE_SIZE / sb->block_size;
    unsigned long pgoff = (unsigned long) logical_block / blocks_per_page;
    struct page *page;

    int st = filemap_find_page(
        ino, pgoff, FIND_PAGE_LOCK | FIND_PAGE_NO_CREATE | FIND_PAGE_NO_RA | FIND_PAGE_NO_READPAGE,
        &page, nullptr);
    if (st < 0)
    {
        /* We couldn't find it (probably), fall back to the disk */
        return -ENOENT;
    }

    /* Page is locked */
    if (!page_flag_set(page, PAGE_FLAG_BUFFER))
    {
        /* Wasn't mapped (yet, at least). Ignore */
        unlock_page(page);
        page_unref(page);
        return -ENOENT;
    }

    unsigned int block_off = (unsigned long) logical_block * sb->block_size - pgoff * PAGE_SIZE;
    for (struct block_buf *b = (struct block_buf *) page->priv; b != nullptr; b = b->next)
    {
        sector_t block = b->block_nr;
        if (b->page_off == block_off)
        {
            *ret = block;
            unlock_page(page);
            page_unref(page);
            return 0;
        }
    }

    /* What?? This should not be possible... */
    CHECK(0);
}

static int ext2_do_bmap_from_inode(struct file *file, unsigned int logical_block, unsigned int *ret)
{
    struct ext2_inode *raw_inode = ext2_get_inode_from_node(file->f_ino);
    ext2_superblock *sb = ext2_superblock_from_inode(file->f_ino);
    auto res = ext2_get_block_from_inode(raw_inode, logical_block, sb);
    if (res.has_error())
        return res.error();
    *ret = res.value();
    return 0;
}

static int do_bmap(struct file *file, unsigned int logical_block, unsigned int *ret)
{
    /* First, try to get it from the block_buf. If not possible, we'll do actual block map
     * traversal. */
    if (ext2_do_bmap_from_page_cache(file, logical_block, ret) == 0)
        return 0;
    return ext2_do_bmap_from_inode(file, logical_block, ret);
}

static unsigned int ext2_ioctl(int request, void *argp, struct file *file)
{
    switch (request)
    {
        case FIBMAP: {
            unsigned int block;
            if (!is_root_user())
                return -EPERM;
            if (copy_from_user(&block, argp, sizeof(block)) < 0)
                return -EFAULT;
            int st = do_bmap(file, block, &block);
            if (st < 0)
                return st;
            return copy_to_user(argp, &block, sizeof(block));
        }
    }

    return -ENOTTY;
}

void ext2_truncate_partial(struct vm_object *vmobj, struct page *page, size_t offset, size_t len)
    REQUIRES(page)
{
    struct inode *ino = vmobj->ino;
    const ext2_superblock *sb = ext2_superblock_from_inode(ino);
    unsigned int start_block_off = cul::align_up2(offset, sb->block_size);
    unsigned int end_block_off = cul::align_down2(offset + len, sb->block_size);
    bool has_blocks = false;

    DCHECK(page_locked(page));
    if (!page_flag_set(page, PAGE_FLAG_BUFFER))
        return;

    for (struct block_buf *b = (struct block_buf *) page->priv; b != nullptr; b = b->next)
    {
        if (b->page_off >= start_block_off && b->page_off < end_block_off)
        {
            /* "Unmap" the block. This is now a hole */
            b->block_nr = 0;
        }

        if (b->block_nr != 0)
            has_blocks = true;
    }

    if (!has_blocks)
    {
        /* If we have no blocks, clean the dirty page */
        filemap_clear_dirty(page);
    }
}
