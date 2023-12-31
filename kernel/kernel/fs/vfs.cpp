/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/buffer.h>
#include <onyx/clock.h>
#include <onyx/cpu.h>
#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/file.h>
#include <onyx/fnv.h>
#include <onyx/gen/trace_writeback.h>
#include <onyx/limits.h>
#include <onyx/log.h>
#include <onyx/mm/flush.h>
#include <onyx/mm/slab.h>
#include <onyx/mtable.h>
#include <onyx/object.h>
#include <onyx/pagecache.h>
#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/sysfs.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

struct file *fs_root = nullptr;
struct file *mount_list = nullptr;

bool inode_is_cacheable(struct inode *file);

struct filesystem_root boot_root = {};

int vfs_init()
{
    object_init(&boot_root.object, nullptr);
    dentry_init();
    file_cache_init();

    return 0;
}

struct filesystem_root *get_filesystem_root()
{
    struct process *p = get_current_process();
    if (!p)
        return &boot_root;

    return &boot_root;
}

struct file *get_fs_root()
{
    struct filesystem_root *root = get_filesystem_root();

    return root->file;
}

#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
uint32_t crc32_calculate(uint8_t *ptr, size_t len);

#endif

/* This function trims the part of the page that wasn't read in(because the segment of
 * the file is smaller than PAGE_SIZE).
 */
static void zero_rest_of_page(struct page *page, size_t to_read)
{
    unsigned char *buf = (unsigned char *) PAGE_TO_VIRT(page) + to_read;

    size_t to_zero = PAGE_SIZE - to_read;

    memset(buf, 0, to_zero);
}

vmo_status_t vmo_inode_commit(struct vm_object *vmo, size_t off, struct page **ppage)
{
    struct inode *i = vmo->ino;

    struct page *page = alloc_page(PAGE_ALLOC_NO_ZERO);
    if (!page)
        return VMO_STATUS_OUT_OF_MEM;

    page->flags |= PAGE_FLAG_BUFFER;
    page->priv = 0;

    size_t to_read = i->i_size - off < PAGE_SIZE ? i->i_size - off : PAGE_SIZE;

    assert(to_read <= PAGE_SIZE);

    unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    assert(i->i_fops->readpage != nullptr);
    ssize_t read = i->i_fops->readpage(page, off, i);

    thread_change_addr_limit(old);

    if (read < (ssize_t) to_read)
    {
#if 0
        printk("Error file read %lx bytes out of %lx, off %lx\n", read, to_read, off);
        perror("file");
#endif
        free_page(page);
        return VMO_STATUS_BUS_ERROR;
    }

    zero_rest_of_page(page, to_read);

    *ppage = page;

    return VMO_STATUS_OK;
}

void inode_free_page(struct vm_object *vmo, struct page *page)
{
#if 0
    struct page_cache_block *b = page->cache;
    if (page->flags & PAGE_FLAG_DIRTY)
    {
        flush_sync_one(&b->fobj);
    }
#endif

    if (page_flag_set(page, PAGE_FLAG_BUFFER))
        page_destroy_block_bufs(page);
    free_page(page);
}

const struct vm_object_ops inode_vmo_ops = {.commit = vmo_inode_commit,
                                            .free_page = inode_free_page};

int inode_create_vmo(struct inode *ino)
{
    ino->i_pages = vmo_create(ino->i_size, nullptr);
    if (!ino->i_pages)
        return -1;
    ino->i_pages->ops = &inode_vmo_ops;
    ino->i_pages->ino = ino;
    return 0;
}

void inode_update_atime(struct inode *ino)
{
    ino->i_atime = clock_get_posix_time();
    inode_mark_dirty(ino);
}

void inode_update_ctime(struct inode *ino)
{
    ino->i_ctime = clock_get_posix_time();
    inode_mark_dirty(ino);
}

void inode_update_mtime(struct inode *ino)
{
    ino->i_mtime = clock_get_posix_time();
    inode_mark_dirty(ino);
}

static size_t clamp_length(size_t len)
{
    return cul::clamp(len, (size_t) SSIZE_MAX);
}

/**
 * @brief Write to a file using iovec_iter, but emulating it using file_operations::write
 *
 * @param filp File pointer
 * @param off Offset
 * @param iter Iterator
 * @param flags Flags
 * @return Written bytes, or negative error code
 */
static ssize_t write_iter_emul(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags)
{
    bool undo;
    ssize_t st;
    struct inode *ino;
    unsigned long addr_lim = 0;

    undo = false;
    st = 0;
    ino = filp->f_ino;

    if (iter->type == IOVEC_KERNEL)
    {
        addr_lim = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
        undo = true;
    }

    while (!iter->empty())
    {
        const auto iov = iter->curiovec();
        ssize_t status = ino->i_fops->write(off, iov.iov_len, iov.iov_base, filp);
        if (status <= 0)
        {
            if (st == 0)
                st = status;
            break;
        }

        st += status;
        if (status != (ssize_t) iov.iov_len)
        {
            /* Partial write, break now */
            break;
        }

        iter->advance(status);
    }

    if (undo)
        thread_change_addr_limit(addr_lim);
    return st;
}

/**
 * @brief Read from a file using iovec_iter, but emulating it using file_operations::read
 *
 * @param filp File pointer
 * @param off Offset
 * @param iter Iterator
 * @param flags Flags
 * @return Read bytes, or negative error code
 */
static ssize_t read_iter_emul(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags)
{
    bool undo;
    ssize_t st;
    struct inode *ino;
    unsigned long addr_lim = 0;

    undo = false;
    st = 0;
    ino = filp->f_ino;

    if (iter->type == IOVEC_KERNEL)
    {
        addr_lim = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
        undo = true;
    }

    while (!iter->empty())
    {
        const auto iov = iter->curiovec();
        ssize_t status = ino->i_fops->read(off, iov.iov_len, iov.iov_base, filp);
        if (status <= 0)
        {
            if (st == 0)
                st = status;
            break;
        }

        st += status;
        if (status != (ssize_t) iov.iov_len)
        {
            /* Partial read, break now */
            break;
        }

        iter->advance(status);
    }

    if (undo)
        thread_change_addr_limit(addr_lim);
    return st;
}

/**
 * @brief Read from a file using iovec_iter
 *
 * @param filp File pointer
 * @param off Offset
 * @param iter Iterator
 * @param flags Flags
 * @return Read bytes, or negative error code
 */
ssize_t read_iter_vfs(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags)
{
    struct inode *ino = filp->f_ino;
    ssize_t st = -EIO;

    if (S_ISDIR(ino->i_mode))
        return -EISDIR;

    if (ino->i_fops->read_iter)
        st = ino->i_fops->read_iter(filp, off, iter, flags);
    else if (ino->i_fops->read)
        st = read_iter_emul(filp, off, iter, flags);

    if (st >= 0)
    {
        if (!(filp->f_flags & O_NOATIME))
            inode_update_atime(ino);
    }

    return st;
}

/**
 * @brief Write to a file using iovec_iter
 *
 * @param filp File pointer
 * @param off Offset
 * @param iter Iterator
 * @param flags Flags
 * @return Written bytes, or negative error code
 */
ssize_t write_iter_vfs(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags)
{
    ssize_t st = -EIO;
    struct inode *ino = filp->f_ino;
    if (S_ISDIR(ino->i_mode))
        return -EISDIR;

    if (ino->i_fops->write_iter) [[likely]]
        st = ino->i_fops->write_iter(filp, off, iter, flags);
    else if (ino->i_fops->write)
        st = write_iter_emul(filp, off, iter, flags);

    if (st >= 0)
        inode_update_mtime(ino);

    return st;
}

ssize_t write_vfs(size_t offset, size_t len, void *buffer, struct file *f)
{
    len = clamp_length(len);
    iovec vec;
    vec.iov_base = buffer;
    vec.iov_len = len;

    iovec_iter iter{{&vec, 1}, len};
    return write_iter_vfs(f, offset, &iter, 0);
}

ssize_t read_vfs(size_t offset, size_t len, void *buffer, struct file *file)
{
    len = clamp_length(len);
    iovec vec;
    vec.iov_base = buffer;
    vec.iov_len = len;

    iovec_iter iter{{&vec, 1}, len};

    return read_iter_vfs(file, offset, &iter, 0);
}

int ioctl_vfs(int request, char *argp, struct file *this_)
{
    if (this_->f_ino->i_fops->ioctl != nullptr)
        return this_->f_ino->i_fops->ioctl(request, (void *) argp, this_);
    return -ENOTTY;
}

void close_vfs(struct inode *this_)
{
    inode_unref(this_);
}

char *readlink_vfs(struct file *file)
{
    if (!S_ISLNK(file->f_ino->i_mode))
        return errno = EINVAL, nullptr;

    if (file->f_ino->i_fops->readlink)
    {
        char *p = file->f_ino->i_fops->readlink(file);
        if (p != nullptr)
            inode_update_atime(file->f_ino);

        return p;
    }

    return errno = EINVAL, nullptr;
}

bool inode_can_access(struct inode *file, unsigned int perms)
{
    bool access_good = true;
    struct creds *c = creds_get();

    if (unlikely(c->euid == 0))
    {
        /* We're root: the access is good */
        // We can always do anything with dirs (exec doesn't mean exec here)
        if (S_ISDIR(file->i_mode))
            goto out;
        // If we're executing, we need a single execute bit set
        if (perms != FILE_ACCESS_EXECUTE || file->i_mode & 0111)
            goto out;
    }

    /* We're not root, let's do permission checking */

    /* Case 1 -  we're the owners of the file (file->uid == c->euid) */

    /* We're going to transform FILE_ACCESS_* constants (our perms var) into UNIX permissions */
    mode_t ino_perms;

    if (likely(file->i_uid == c->euid))
    {
        ino_perms = ((perms & FILE_ACCESS_READ) ? S_IRUSR : 0) |
                    ((perms & FILE_ACCESS_WRITE) ? S_IWUSR : 0) |
                    ((perms & FILE_ACCESS_EXECUTE) ? S_IXUSR : 0);
    }
    else if (file->i_gid == c->egid || cred_is_in_group(c, file->i_gid))
    {
        /* Case 2 - we're in the same group as the file */
        ino_perms = ((perms & FILE_ACCESS_READ) ? S_IRGRP : 0) |
                    ((perms & FILE_ACCESS_WRITE) ? S_IWGRP : 0) |
                    ((perms & FILE_ACCESS_EXECUTE) ? S_IXGRP : 0);
    }
    else
    {
        /* Case 3 - others permissions apply */
        ino_perms = ((perms & FILE_ACCESS_READ) ? S_IROTH : 0) |
                    ((perms & FILE_ACCESS_WRITE) ? S_IWOTH : 0) |
                    ((perms & FILE_ACCESS_EXECUTE) ? S_IXOTH : 0);
    }

    /* Now, test the calculated permission bits against the file's mode */

    access_good = (file->i_mode & ino_perms) == ino_perms;

#if 0
    if (!access_good)
    {
        panic("Halting for debug: ino perms %o, perms %o\n", ino_perms, file->i_mode);
    }
#endif
out:
    creds_put(c);
    return access_good;
}

bool file_can_access(struct file *file, unsigned int perms)
{
    return inode_can_access(file->f_ino, perms);
}

off_t do_getdirent(struct dirent *buf, off_t off, struct file *file)
{
    /* FIXME: Detect when we're trying to list unlinked directories, lock the dentry, etc... */
    if (file->f_ino->i_fops->getdirent != nullptr)
        return file->f_ino->i_fops->getdirent(buf, off, file);
    return -ENOSYS;
}

unsigned int putdir(struct dirent *buf, struct dirent *ubuf, unsigned int count)
{
    unsigned int reclen = buf->d_reclen;

    if (reclen > count)
        return errno = EINVAL, -1;

    if (copy_to_user(ubuf, buf, reclen) < 0)
    {
        errno = EFAULT;
        return -1;
    }

    return reclen > count ? count : reclen;
}

int getdents_vfs(unsigned int count, putdir_t putdir, struct dirent *dirp, off_t off,
                 struct getdents_ret *ret, struct file *f)
{
    if (!S_ISDIR(f->f_ino->i_mode))
        return errno = ENOTDIR, -1;

    if (!file_can_access(f, FILE_ACCESS_READ))
        return errno = EACCES, -1;

    // printk("Seek: %lu\n", off);
    // printk("Count: %u\n", count);
    struct dirent buf;
    unsigned int pos = 0;

    while (pos < count)
    {
        off_t of = do_getdirent(&buf, off, f);
#if 0
		printk("of: %lu\n", of);
		printk("Dirent: %s\n", buf.d_name);
		printk("pos: %u\n", pos);
		printk("count: %u\n", count);
		printk("dirp %p\n", dirp);
#endif

        if (of == 0)
        {
            // printk("EOF\n");
            if (pos)
                return pos;
            return 0;
        }

        /* Error, return -1 with errno set */
        if (of < 0)
            return errno = -of, -1;

        /* Align d_reclen to a size aligned to alignof(struct dirent) */
        buf.d_reclen = ALIGN_TO(buf.d_reclen, alignof(struct dirent));

        /* Put the dirent in the user-space buffer */
        unsigned int written = putdir(&buf, dirp, count - pos);
        /* Error, most likely out of buffer space */
        if (written == (unsigned int) -1)
        {
            // printk("Buf: %p\n", dirp);
            if (!pos)
                return -1;
            else
                return pos;
        }

        // printk("Written: %u\n", written);

        pos += written;
        dirp = (dirent *) ((char *) dirp + written);
        off = of;
        ret->read = pos;
        ret->new_off = off;
    }

    return pos;
}

int default_stat(struct stat *buf, struct file *f)
{
    struct inode *ino = f->f_ino;

    buf->st_atime = ino->i_atime;
    buf->st_ctime = ino->i_ctime;
    buf->st_mtime = ino->i_mtime;

    buf->st_blksize = ino->i_sb ? ino->i_sb->s_block_size : PAGE_SIZE;
    buf->st_blocks = ino->i_blocks;
    buf->st_dev = ino->i_dev;
    buf->st_gid = ino->i_gid;
    buf->st_uid = ino->i_uid;
    buf->st_ino = ino->i_inode;
    buf->st_mode = ino->i_mode;
    buf->st_nlink = ino->i_nlink;
    buf->st_rdev = ino->i_rdev;
    buf->st_size = ino->i_size;

    return 0;
}

int stat_vfs(struct stat *buf, struct file *node)
{
    if (node->f_ino->i_fops->stat != nullptr)
        return node->f_ino->i_fops->stat(buf, node);
    else
    {
        return default_stat(buf, node);
    }
}

short default_poll(void *poll_table, short events, struct file *node);

short poll_vfs(void *poll_file, short events, struct file *node)
{
    if (node->f_ino->i_fops->poll != nullptr)
        return node->f_ino->i_fops->poll(poll_file, events, node);

    return default_poll(poll_file, events, node);
}

bool inode_is_cacheable(struct inode *ino)
{
    if (ino->i_flags & INODE_FLAG_DONT_CACHE)
        return false;

    /* TODO: Find a better solution here. Set a flag for when the inode has a cache maybe?
     * Or use the .read and .write function pointers.
     */

    if (!S_ISREG(ino->i_mode) && !S_ISDIR(ino->i_mode) && !S_ISLNK(ino->i_mode))
        return false;

    return true;
}

int default_ftruncate(off_t length, struct file *f)
{
    if (length < 0)
        return -EINVAL;
    struct inode *vnode = f->f_ino;

    if ((size_t) length <= vnode->i_size)
    {
        /* Possible memory/disk leak, but filesystems should handle it */
        vnode->i_size = (size_t) length;
        return 0;
    }

    char *page = (char *) zalloc(PAGE_SIZE);
    if (!page)
    {
        return -ENOMEM;
    }

    printk("Default ftruncate\n");

    size_t length_diff = (size_t) length - vnode->i_size;
    size_t off = vnode->i_size;

    while (length_diff != 0)
    {
        size_t to_write = length_diff >= PAGE_SIZE ? PAGE_SIZE : length_diff;

        unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
        size_t written = write_vfs(off, to_write, page, f);

        thread_change_addr_limit(old);
        if (written != to_write)
        {
            free(page);
            return -errno;
        }

        off += to_write;
        length_diff -= to_write;
    }

    free(page);

    return 0;
}

int ftruncate_vfs(off_t length, struct file *vnode)
{
    if (length < 0)
        return -EINVAL;

    if (S_ISDIR(vnode->f_ino->i_mode))
        return -EISDIR;

    if ((size_t) length == vnode->f_ino->i_size)
        return 0;

    rw_lock_write(&vnode->f_ino->i_rwlock);

    int st = 0;
    if (vnode->f_ino->i_fops->ftruncate != nullptr)
        st = vnode->f_ino->i_fops->ftruncate(length, vnode);
    else
    {
        st = default_ftruncate(length, vnode);
    }

    rw_unlock_write(&vnode->f_ino->i_rwlock);

    return st;
}

int default_fallocate(int mode, off_t offset, off_t len, struct file *file)
{
    /* VERY VERY VERY VERY VERY quick and dirty implementation to satisfy /bin/ld(.gold) */
    if (mode != 0)
        return -EINVAL;

    char *page = (char *) zalloc(PAGE_SIZE);
    if (!page)
    {
        return -ENOMEM;
    }

    size_t length_diff = (size_t) len;
    size_t off = offset;
    while (length_diff != 0)
    {
        size_t to_write = length_diff >= PAGE_SIZE ? PAGE_SIZE : length_diff;

        size_t written = write_vfs(off, to_write, page, file);

        if (written != to_write)
        {
            free(page);
            return (int) written;
        }

        off += to_write;
        length_diff -= to_write;
    }

    free(page);

    return 0;
}

int fallocate_vfs(int mode, off_t offset, off_t len, struct file *file)
{
    if (file->f_ino->i_fops->fallocate)
    {
        return file->f_ino->i_fops->fallocate(mode, offset, len, file);
    }
    else
        return default_fallocate(mode, offset, len, file);

    return -EINVAL;
}

int inode_init(struct inode *inode, bool is_cached)
{
    /* Note: (void *) to shut up GCC's -Wclass-memaccess */
    memset((void *) inode, 0, sizeof(struct inode));

    inode->i_refc = 1;
    if (is_cached)
    {
        if (inode_create_vmo(inode) < 0)
        {
            return -ENOMEM;
        }
    }

    spinlock_init(&inode->i_lock);
    rwlock_init(&inode->i_rwlock);

    return 0;
}

bool inode_no_dirty(struct inode *ino, unsigned int flags)
{
    if (!ino->i_sb)
        return true;
    if (!(ino->i_sb->s_flags & SB_FLAG_NODIRTY))
        return false;

    /* If NODIRTY, check if we are a block device, and that we are dirtying pages */
    if (S_ISBLK(ino->i_mode))
        return !(flags & I_DATADIRTY);
    return true;
}

void inode_mark_dirty(struct inode *ino, unsigned int flags)
{
    /* FIXME: Ugh, leaky abstractions... */
    if (inode_no_dirty(ino, flags))
        return;

    DCHECK(flags & I_DIRTYALL);

    /* Already dirty */
    if ((ino->i_flags & flags) == flags)
        return;

    auto dev = bdev_get_wbdev(ino);
    dev->lock();
    spin_lock(&ino->i_lock);

    unsigned int old_flags = ino->i_flags;

    ino->i_flags |= flags;
    trace_wb_dirty_inode(ino->i_inode, ino->i_dev);

    /* The writeback code will take care of redirtying if need be */
    if (!(old_flags & (I_WRITEBACK | I_DIRTYALL)))
        dev->add_inode(ino);

    spin_unlock(&ino->i_lock);
    dev->unlock();
}

struct file *inode_to_file(struct inode *ino)
{
    struct file *f = file_alloc();
    if (!f)
        return nullptr;

    new (f) file;
    f->f_ino = ino;
    f->f_flags = 0;
    f->f_refcount = 1;
    f->f_seek = 0;
    f->f_dentry = nullptr;

    return f;
}

/**
 * @brief Getdirent helper
 *
 * @param buf Pointer to struct dirent
 * @param dentry Pointer to dentry
 * @param special_name Special name if the current dentry is "." or ".."
 */
void put_dentry_to_dirent(struct dirent *buf, dentry *dentry, const char *special_name)
{
    auto ino = dentry->d_inode;

    const char *name = special_name ?: dentry->d_name;

    buf->d_ino = ino->i_inode;
    auto len = strlen(name);
    memcpy(buf->d_name, name, len);
    buf->d_name[len] = '\0';
    buf->d_reclen = sizeof(dirent) - (256 - (len + 1));

    if (S_ISDIR(ino->i_mode))
        buf->d_type = DT_DIR;
    else if (S_ISBLK(ino->i_mode))
        buf->d_type = DT_BLK;
    else if (S_ISCHR(ino->i_mode))
        buf->d_type = DT_CHR;
    else if (S_ISLNK(ino->i_mode))
        buf->d_type = DT_LNK;
    else if (S_ISREG(ino->i_mode))
        buf->d_type = DT_REG;
    else if (S_ISSOCK(ino->i_mode))
        buf->d_type = DT_SOCK;
    else if (S_ISFIFO(ino->i_mode))
        buf->d_type = DT_FIFO;
    else
        buf->d_type = DT_UNKNOWN;
}

/**
 * @brief Applies setuid and setgid permissions
 *
 * @param f File
 * @return True if applied, else false
 */
bool apply_sugid_permissions(file *f)
{
    auto ino = f->f_ino;
    if (!(ino->i_mode & (S_ISGID | S_ISUID)))
        return false;

    creds_guard<CGType::Write> g;

    if (ino->i_mode & S_ISUID)
    {
        g.get()->euid = ino->i_uid;
    }

    if (ino->i_mode & S_ISGID)
    {
        g.get()->egid = ino->i_gid;
    }

    return true;
}
