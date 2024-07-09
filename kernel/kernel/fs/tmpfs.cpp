/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/cred.h>
#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/filemap.h>
#include <onyx/fs_mount.h>
#include <onyx/log.h>
#include <onyx/mutex.h>
#include <onyx/page.h>
#include <onyx/tmpfs.h>
#include <onyx/vfs.h>

#include <uapi/fcntl.h>
#include <uapi/memstat.h>

#include <onyx/atomic.hpp>

// TODO: Parts of this should definitely be separated as they're generic enough
// for every pseudo filesystem we might want to stick in Onyx

static DECLARE_MUTEX(tmpfs_list_lock);
static struct list_head filesystems = LIST_HEAD_INIT(filesystems);

atomic<ino_t> tmpfs_superblock::curr_minor_number{1};

tmpfs_inode *tmpfs_create_inode(mode_t mode, struct dentry *dir, dev_t rdev = 0)
{
    auto dir_inode = dir->d_inode;
    auto sb = (tmpfs_superblock *) dir_inode->i_sb;
    return sb->create_inode(mode, rdev);
}

struct inode *tmpfs_creat(struct dentry *dentry, int mode, struct dentry *dir)
{
    return tmpfs_create_inode(static_cast<mode_t>(S_IFREG | mode), dir);
}

int tmpfs_link(struct file *target_ino, const char *name, struct dentry *dir)
{
    return 0;
}

inode *tmpfs_symlink(struct dentry *dentry, const char *dest, struct dentry *dir)
{
    const char *link_name = strdup(dest);
    if (!link_name)
        return nullptr;

    auto new_ino = tmpfs_create_inode(S_IFLNK | 0777, dir);
    if (!new_ino)
    {
        free((void *) link_name);
        return nullptr;
    }

    new_ino->link = link_name;

    return new_ino;
}

inode *tmpfs_mkdir(struct dentry *dentry, mode_t mode, struct dentry *dir)
{
    return tmpfs_create_inode(mode | S_IFDIR, dir);
}

inode *tmpfs_mknod(struct dentry *dentry, mode_t mode, dev_t dev, struct dentry *dir)
{
    return tmpfs_create_inode(mode, dir, dev);
}

char *tmpfs_readlink(struct file *f)
{
    tmpfs_inode *ino = static_cast<tmpfs_inode *>(f->f_ino);

    return strdup(ino->link);
}

int tmpfs_unlink(const char *name, int flags, struct dentry *dir)
{
    auto child = dentry_lookup_internal(name, dir, 0);
    assert(child != nullptr);

    if (S_ISDIR(child->d_inode->i_mode))
    {
        if (!(flags & AT_REMOVEDIR))
            return -EISDIR;
        if (!(flags & UNLINK_VFS_DONT_TEST_EMPTY) && !dentry_is_empty(child))
            return -ENOTEMPTY;
    }

    dentry_put(child);

    return 0;
}

ssize_t tmpfs_readpage(struct page *page, size_t offset, struct inode *ino)
{
    memset(PAGE_TO_VIRT(page), 0, PAGE_SIZE);
    page->flags |= PAGE_FLAG_UPTODATE;
    inc_page_stat(page, NR_SHARED);
    return PAGE_SIZE;
}

ssize_t tmpfs_writepage(struct page *page, size_t offset, struct inode *ino) REQUIRES(page)
    RELEASE(page)
{
    unlock_page(page);
    return PAGE_SIZE;
}

int tmpfs_open(struct dentry *dir, const char *name, struct dentry *dentry)
{
    /* This a no-op, since names are either cached or non-existent in our tmpfs */
    return -ENOENT;
}

off_t tmpfs_getdirent(struct dirent *buf, off_t off, struct file *file)
{
    auto dent = file->f_dentry;

    buf->d_off = off;

    if (off == 0)
    {
        /* . */
        put_dentry_to_dirent(buf, dent, ".");
    }
    else if (off == 1)
    {
        /* .. */
        auto parent = dentry_parent(dent);
        if (!parent) // We're root, so use ourselves
            parent = dent;
        put_dentry_to_dirent(buf, parent, "..");
        dentry_put(parent);
    }
    else
    {
        scoped_rwslock<rw_lock::read> g(dent->d_lock);

        off_t c = 0;
        list_for_every (&dent->d_children_head)
        {
            auto d = container_of(l, dentry, d_parent_dir_node);

            if (d_is_negative(d))
                continue;

            if (off > c++ + 2)
                continue;

            put_dentry_to_dirent(buf, d);
            return off + 1;
        }

        return 0;
    }

    return off + 1;
}

int tmpfs_prepare_write(inode *ino, struct page *page, size_t page_off, size_t offset, size_t len)
{
    // If PAGE_FLAG_FILESYSTEM1 is not set, we have not seen this page. Add to blocks and make sure
    // we dont count this in ino->i_blocks again.
    if (!(page->flags & PAGE_FLAG_FILESYSTEM1))
    {
        ino->i_blocks += PAGE_SIZE / 512;
        page->flags |= PAGE_FLAG_FILESYSTEM1;

        ((tmpfs_superblock *) ino->i_sb)->nblocks++;
        // TODO: Decrement this when truncating/killing inodes
    }

    return 0;
}

void tmpfs_close(inode *file)
{
    tmpfs_inode *ino = (tmpfs_inode *) file;

    if (ino->link)
        free((void *) ino->link);
    ((tmpfs_superblock *) ino->i_sb)->ino_nr--;
}

int tmpfs_ftruncate(size_t len, file *f)
{
    int st = vmo_truncate(f->f_ino->i_pages, len, 0);

    if (st < 0)
        return st;
    f->f_ino->i_size = len;
    return 0;
}

struct file_ops tmpfs_fops = {.read = nullptr,
                              .write = nullptr,
                              .open = tmpfs_open,
                              .close = tmpfs_close,
                              .getdirent = tmpfs_getdirent,
                              .ioctl = nullptr,
                              .creat = tmpfs_creat,
                              .stat = nullptr,
                              .link = tmpfs_link,
                              .symlink = tmpfs_symlink,
                              .mmap = nullptr,
                              .ftruncate = tmpfs_ftruncate,
                              .mkdir = tmpfs_mkdir,
                              .mknod = tmpfs_mknod,
                              .on_open = nullptr,
                              .poll = nullptr,
                              .readlink = tmpfs_readlink,
                              .unlink = tmpfs_unlink,
                              .fallocate = nullptr,
                              .readpage = tmpfs_readpage,
                              .writepage = tmpfs_writepage,
                              .prepare_write = tmpfs_prepare_write,
                              .read_iter = filemap_read_iter,
                              .write_iter = filemap_write_iter};

static void tmpfs_free_page(struct vm_object *vmo, struct page *page)
{
    if (page_flag_set(page, PAGE_FLAG_UPTODATE))
        dec_page_stat(page, NR_SHARED);
    free_page(page);
}

const static vm_object_ops tmpfs_vmops = {
    .free_page = tmpfs_free_page,
};

/**
 * @brief Allocate a tmpfs inode
 * Note: unlike create_inode, this function does not add an inode to the cache, set nlink to 1,
 * etc.
 *
 * @param mode Inode's mode
 * @param rdev rdev
 * @return The created tmpfs_inode, or NULL
 */
tmpfs_inode *tmpfs_superblock::alloc_inode(mode_t mode, dev_t rdev)
{
    auto ino = make_unique<tmpfs_inode>();
    if (!ino)
        return nullptr;

    if (ino->init(mode) < 0)
    {
        return nullptr;
    }

    ino->i_fops = tmpfs_ops_;

    ino->i_nlink = 0;
    if (ino->i_pages)
        ino->i_pages->ops = &tmpfs_vmops;

    /* We're currently holding two refs: one for the user, and another for the simple fact
     * that we need this inode to remain in memory.
     */

    auto c = creds_get();

    ino->i_mode = mode;
    ino->i_ctime = ino->i_atime = ino->i_mtime = clock_get_posix_time();
    ino->i_dev = s_devnr;
    ino->i_inode = curr_inode.fetch_add(1);
    ino->i_gid = c->egid;
    ino->i_uid = c->euid;
    creds_put(c);

    ino->i_rdev = rdev;
    ino->i_sb = this;
    ino->i_rdev = rdev;
    ino->i_blocks = 0;

    if (inode_is_special(ino.get()))
    {
        int st = inode_special_init(ino.get());
        if (st < 0)
        {
            errno = -st;
            return nullptr;
        }
    }

    ino_nr++;

    return ino.release();
}

tmpfs_inode *tmpfs_superblock::create_inode(mode_t mode, dev_t rdev)
{
    tmpfs_inode *inode = alloc_inode(mode, rdev);
    if (!inode)
        return nullptr;
    inode->i_nlink = 1;
    superblock_add_inode(this, inode);

    /* Now, refcount should equal 3, because the inode cache just grabbed it... */
    return inode;
}

static void tmpfs_append(tmpfs_superblock *fs)
{
    mutex_lock(&tmpfs_list_lock);

    list_add_tail(&fs->fs_list_node, &filesystems);

    mutex_unlock(&tmpfs_list_lock);
}

tmpfs_superblock *tmpfs_create_sb()
{
    tmpfs_superblock *new_fs = new tmpfs_superblock{};
    if (!new_fs)
        return nullptr;

    tmpfs_append(new_fs);
    return new_fs;
}

/**
 * @brief Mount a tmpfs instance
 *
 * @param dev Traditionally a pointer to blockdev, but our case, unused.
 * @return Pointer to the root inode, or nullptr in case of an error
 */
inode *tmpfs_mount(blockdev *bdev)
{
    LOG("tmpfs", "Mounting a new instance of tmpfs\n");

    auto new_sb = tmpfs_create_sb();
    if (!new_sb)
        return errno = ENOMEM, nullptr;

    char name[NAME_MAX + 1];
    snprintf(name, NAME_MAX, "tmpfs-%lu", new_sb->fs_minor);

    auto ex = dev_register_blockdevs(0, 1, 0, nullptr, name);

    if (ex.has_error())
        return errno = -ex.error(), nullptr;

    auto blockdev = ex.value();

    new_sb->s_devnr = blockdev->dev();

    auto node = new_sb->create_inode(S_IFDIR | 1777);
    if (!node)
    {
        dev_unregister_dev(blockdev, true);
        delete new_sb;
        return errno = ENOMEM, nullptr;
    }

    return node;
}

/**
 * @brief Tmpfs mount kernel helper function
 *
 * @param mountpoint Path where to mount the new tmpfs instance
 * @return 0 on success, else negative error codes
 */
int tmpfs_kern_mount(const char *mountpoint)
{
    LOG("tmpfs", "Mounting on %s\n", mountpoint);

    auto node = tmpfs_mount(nullptr);

    if (!node)
        return -errno;

    if (mount_fs(node, mountpoint) < 0)
    {
        // TODO: Destroy the filesystem or something
        return -errno;
    }

    return 0;
}

__init void tmpfs_init()
{
    if (auto st = fs_mount_add(tmpfs_mount, FS_MOUNT_PSEUDO_FS, "tmpfs"); st < 0)
        ERROR("tmpfs", "Failed to register tmpfs - error %d", st);
}

#define TMPFS_MAGIC 0x11102002

int tmpfs_statfs(struct statfs *buf, struct superblock *sb)
{
    tmpfs_superblock *s = (tmpfs_superblock *) sb;
    buf->f_type = TMPFS_MAGIC;
    buf->f_bsize = PAGE_SIZE;
    struct memstat mbuf;
    page_get_stats(&mbuf);
    buf->f_bavail = buf->f_blocks = mbuf.total_pages - mbuf.allocated_pages;
    buf->f_blocks = s->nblocks;
    buf->f_files = s->ino_nr;
    memset(&buf->f_fsid, 0, sizeof(buf->f_fsid));
    buf->f_ffree = 0xffffffff;
    buf->f_namelen = NAME_MAX;
    buf->f_flags = 0;
    return 0;
}
