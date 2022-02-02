/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <onyx/compiler.h>
#include <onyx/dentry.h>
#include <onyx/file.h>
#include <onyx/fs_mount.h>
#include <onyx/limits.h>
#include <onyx/panic.h>
#include <onyx/pipe.h>
#include <onyx/process.h>
#include <onyx/user.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

bool is_absolute_filename(const char *file)
{
    return *file == '/' ? true : false;
}

struct file *get_fs_base(const char *file, struct file *rel_base)
{
    return is_absolute_filename(file) == true ? get_fs_root() : rel_base;
}

struct file *get_current_directory(void)
{
    struct ioctx *ctx = &get_current_process()->ctx;
    spin_lock(&ctx->cwd_lock);

    struct file *fp = ctx->cwd;

    if (unlikely(!fp))
    {
        spin_unlock(&ctx->cwd_lock);
        return nullptr;
    }

    fd_get(fp);

    spin_unlock(&ctx->cwd_lock);
    return fp;
}

void fd_get(struct file *fd)
{
    __sync_add_and_fetch(&fd->f_refcount, 1);
}

void fd_put(struct file *fd)
{
    if (__sync_sub_and_fetch(&fd->f_refcount, 1) == 0)
    {
        close_vfs(fd->f_ino);
        // printk("file %s dentry refs %lu\n", fd->f_dentry->d_name, fd->f_dentry->d_ref);
        dentry_put(fd->f_dentry);
        free(fd);
    }
}

static inline bool fd_is_open(int fd, struct ioctx *ctx)
{
    unsigned long long_idx = fd / FDS_PER_LONG;
    unsigned long bit_idx = fd % FDS_PER_LONG;
    return ctx->open_fds[long_idx] & (1UL << bit_idx);
}

static bool validate_fd_number(int fd, struct ioctx *ctx)
{
    if (fd < 0)
    {
        return false;
    }

    if ((unsigned int)fd >= ctx->file_desc_entries)
    {
        return false;
    }

    if (!fd_is_open(fd, ctx))
    {
        return false;
    }

    return true;
}

static inline void fd_close_bit(int fd, struct ioctx *ctx)
{
    unsigned long long_idx = fd / FDS_PER_LONG;
    unsigned long bit_idx = fd % FDS_PER_LONG;
    ctx->open_fds[long_idx] &= ~(1UL << bit_idx);
}

void fd_set_cloexec(int fd, bool toggle, struct ioctx *ctx)
{
    unsigned long long_idx = fd / FDS_PER_LONG;
    unsigned long bit_idx = fd % FDS_PER_LONG;

    if (toggle)
        ctx->cloexec_fds[long_idx] |= (1UL << bit_idx);
    else
        ctx->cloexec_fds[long_idx] &= ~(1UL << bit_idx);
}

void fd_set_open(int fd, bool toggle, struct ioctx *ctx)
{
    unsigned long long_idx = fd / FDS_PER_LONG;
    unsigned long bit_idx = fd % FDS_PER_LONG;

    if (toggle)
        ctx->open_fds[long_idx] |= (1UL << bit_idx);
    else
        ctx->open_fds[long_idx] &= ~(1UL << bit_idx);
}

bool fd_is_cloexec(int fd, struct ioctx *ctx)
{
    unsigned long long_idx = fd / FDS_PER_LONG;
    unsigned long bit_idx = fd % FDS_PER_LONG;

    return ctx->cloexec_fds[long_idx] & (1UL << bit_idx);
}

struct file *__get_file_description_unlocked(int fd, struct process *p)
{
    struct ioctx *ctx = &p->ctx;

    if (!validate_fd_number(fd, ctx))
        return errno = EBADF, nullptr;

    struct file *f = ctx->file_desc[fd];
    fd_get(f);

    return f;
}

struct file *__get_file_description(int fd, struct process *p)
{
    struct ioctx *ctx = &p->ctx;

    mutex_lock(&ctx->fdlock);

    struct file *f = __get_file_description_unlocked(fd, p);

    mutex_unlock(&ctx->fdlock);

    return f;
}

int __file_close_unlocked(int fd, struct process *p)
{
    // printk("pid %d close %d\n", get_current_process()->pid, fd);
    struct ioctx *ctx = &p->ctx;

    if (!validate_fd_number(fd, ctx))
        return -EBADF;

    struct file *f = ctx->file_desc[fd];

    /* Decrement the ref count and set the entry to nullptr */
    /* TODO: Shrink the fd table? */
    fd_put(f);

    ctx->file_desc[fd] = nullptr;
    fd_close_bit(fd, ctx);

    return 0;
}

int __file_close(int fd, struct process *p)
{
    struct ioctx *ctx = &p->ctx;

    mutex_lock(&ctx->fdlock);

    int ret = __file_close_unlocked(fd, p);

    mutex_unlock(&ctx->fdlock);

    return ret;
}

int file_close(int fd)
{
    return __file_close(fd, get_current_process());
}

struct file *get_file_description(int fd)
{
    return __get_file_description(fd, get_current_process());
}

int copy_file_descriptors(struct process *process, struct ioctx *ctx)
{
    scoped_mutex g{ctx->fdlock};

    process->ctx.file_desc = (file **)malloc(ctx->file_desc_entries * sizeof(void *));
    process->ctx.file_desc_entries = ctx->file_desc_entries;
    if (!process->ctx.file_desc)
    {
        return -ENOMEM;
    }

    process->ctx.cloexec_fds = (unsigned long *)malloc(ctx->file_desc_entries / 8);
    if (!process->ctx.cloexec_fds)
    {
        free(process->ctx.file_desc);
        return -ENOMEM;
    }

    process->ctx.open_fds = (unsigned long *)malloc(ctx->file_desc_entries / 8);
    if (!process->ctx.open_fds)
    {
        free(process->ctx.file_desc);
        free(process->ctx.cloexec_fds);
        return -ENOMEM;
    }

    memcpy(process->ctx.cloexec_fds, ctx->cloexec_fds, ctx->file_desc_entries / 8);
    memcpy(process->ctx.open_fds, ctx->open_fds, ctx->file_desc_entries / 8);

    for (unsigned int i = 0; i < process->ctx.file_desc_entries; i++)
    {
        process->ctx.file_desc[i] = ctx->file_desc[i];
        if (fd_is_open(i, &process->ctx))
            fd_get(ctx->file_desc[i]);
    }

    return 0;
}

int allocate_file_descriptor_table(struct process *process)
{
    process->ctx.file_desc = (file **)zalloc(FILE_DESCRIPTOR_GROW_NR * sizeof(void *));
    if (!process->ctx.file_desc)
        return -ENOMEM;

    process->ctx.file_desc_entries = FILE_DESCRIPTOR_GROW_NR;

    process->ctx.cloexec_fds = (unsigned long *)zalloc(FILE_DESCRIPTOR_GROW_NR / 8);
    if (!process->ctx.cloexec_fds)
    {
        free(process->ctx.file_desc);
        return -ENOMEM;
    }

    process->ctx.open_fds = (unsigned long *)zalloc(FILE_DESCRIPTOR_GROW_NR / 8);
    if (!process->ctx.open_fds)
    {
        free(process->ctx.file_desc);
        free(process->ctx.cloexec_fds);
        return -1;
    }

    return 0;
}

#define FD_ENTRIES_TO_FDSET_SIZE(x) ((x) / 8)

/* Enlarges the file descriptor table by FILE_DESCRIPTOR_GROW_NR(64) entries */
int enlarge_file_descriptor_table(struct process *process, unsigned int new_size)
{
    unsigned int old_nr_fds = process->ctx.file_desc_entries;

    new_size = ALIGN_TO(new_size, FILE_DESCRIPTOR_GROW_NR);

    process->ctx.file_desc_entries = new_size;

    if (new_size > INT_MAX || new_size >= process->get_rlimit(RLIMIT_NOFILE).rlim_cur)
        return -EMFILE;

    unsigned int new_nr_fds = process->ctx.file_desc_entries;

    struct file **table = (file **)malloc(process->ctx.file_desc_entries * sizeof(void *));
    unsigned long *cloexec_fds = (unsigned long *)malloc(FD_ENTRIES_TO_FDSET_SIZE(new_nr_fds));
    /* We use zalloc here to implicitly zero free fds */
    unsigned long *open_fds = (unsigned long *)zalloc(FD_ENTRIES_TO_FDSET_SIZE(new_nr_fds));
    if (!table || !cloexec_fds || !open_fds)
        goto error;

    /* Note that we use old_nr_fds for these copies specifically as to not go
     * out of bounds.
     */
    memcpy(table, process->ctx.file_desc, (old_nr_fds) * sizeof(void *));
    memcpy(cloexec_fds, process->ctx.cloexec_fds, FD_ENTRIES_TO_FDSET_SIZE(old_nr_fds));
    memcpy(open_fds, process->ctx.open_fds, FD_ENTRIES_TO_FDSET_SIZE(old_nr_fds));

    free(process->ctx.cloexec_fds);
    free(process->ctx.open_fds);
    free(process->ctx.file_desc);

    process->ctx.file_desc = table;
    process->ctx.cloexec_fds = cloexec_fds;
    process->ctx.open_fds = open_fds;

    return 0;

error:
    free(table);
    free(cloexec_fds);
    free(open_fds);

    /* Don't forget to restore the old file_desc_entries! */
    process->ctx.file_desc_entries = old_nr_fds;

    return -ENOMEM;
}

void process_destroy_file_descriptors(process *process)
{
    ioctx *ctx = &process->ctx;
    file **table = ctx->file_desc;
    mutex_lock(&ctx->fdlock);

    for (unsigned int i = 0; i < ctx->file_desc_entries; i++)
    {
        if (!fd_is_open(i, ctx))
            continue;

        fd_put(table[i]);
    }

    free(table);

    ctx->file_desc = nullptr;
    ctx->file_desc_entries = 0;

    mutex_unlock(&ctx->fdlock);
}

int alloc_fd(int fdbase)
{
    auto current = get_current_process();
    struct ioctx *ioctx = &current->ctx;
    mutex_lock(&ioctx->fdlock);

    unsigned long starting_long = fdbase / FDS_PER_LONG;

    while (true)
    {
        unsigned long nr_longs = ioctx->file_desc_entries / FDS_PER_LONG;

        for (unsigned long i = starting_long; i < nr_longs; i++)
        {
            if (ioctx->open_fds[i] == ULONG_MAX)
                continue;

            /* We speed it up by doing an ffz. */
            unsigned int first_free = __builtin_ctzl(~ioctx->open_fds[i]);

            for (unsigned int j = first_free; j < FDS_PER_LONG; j++)
            {
                int fd = FDS_PER_LONG * i + j;

                if (ioctx->open_fds[i] & (1UL << j))
                    continue;

                if (fd < fdbase)
                    continue;
                else
                {
                    /* Check against the file limit */
                    if (current->get_rlimit(RLIMIT_NOFILE).rlim_cur < (unsigned long)fd)
                        return -EMFILE;
                    /* Found a free fd that we can use, let's mark it used and return it */
                    ioctx->open_fds[i] |= (1UL << j);
                    /* And don't forget to reset the cloexec flag! */
                    fd_set_cloexec(fd, false, ioctx);
                    return fd;
                }
            }
        }

        /* TODO: Make it so we can enlarge it directly to the size we want */
        int new_entries = ioctx->file_desc_entries + FILE_DESCRIPTOR_GROW_NR;
        if (enlarge_file_descriptor_table(current, new_entries) < 0)
        {
            mutex_unlock(&ioctx->fdlock);
            return -ENOMEM;
        }
    }
}

int file_alloc(struct file *f, struct ioctx *ioctx)
{
    int filedesc = alloc_fd(0);
    if (filedesc < 0)
        return errno = -filedesc, filedesc;

    ioctx->file_desc[filedesc] = f;
    fd_get(f);

    return filedesc;
}

ssize_t sys_read(int fd, const void *buf, size_t count)
{
    auto_file f = get_file_description(fd);
    if (!f)
        return -errno;

    auto fil = f.get_file();

    if (!fd_may_access(fil, FILE_ACCESS_READ))
        return -EBADF;

    ssize_t size = read_vfs(fil->f_seek, count, (char *)buf, fil);
    if (size < 0)
    {
        return -errno;
    }

    /* TODO: Seek adjustments are required to be atomic */
    __sync_add_and_fetch(&fil->f_seek, size);

    return size;
}

ssize_t sys_write(int fd, const void *buf, size_t count)
{
    auto_file f = get_file_description(fd);
    if (!f)
        return -errno;

    auto fil = f.get_file();

    if (!fd_may_access(fil, FILE_ACCESS_WRITE))
    {
        return -EBADF;
    }

    if (fil->f_flags & O_APPEND)
        fil->f_seek = fil->f_ino->i_size;

    auto written = write_vfs(fil->f_seek, count, (void *)buf, fil);

    if (written == -1)
        return -errno;

    __sync_add_and_fetch(&fil->f_seek, written);

    return written;
}

ssize_t sys_pread(int fd, void *buf, size_t count, off_t offset)
{
    auto_file f = get_file_description(fd);
    if (!f)
        return -errno;

    auto fil = f.get_file();

    if (!fd_may_access(fil, FILE_ACCESS_READ))
    {
        return -EBADF;
    }

    if (offset < 0)
    {
        return -EINVAL;
    }

    ssize_t size = read_vfs(offset, count, (char *)buf, fil);
    if (size < 0)
    {
        return -errno;
    }

    return size;
}

ssize_t sys_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    auto_file f = get_file_description(fd);
    if (!f)
        return -errno;

    auto fil = f.get_file();

    if (!fd_may_access(fil, FILE_ACCESS_WRITE))
    {
        return -EBADF;
    }

    if (offset < 0)
    {
        return -EINVAL;
    }

    ssize_t written = write_vfs(offset, count, (void *)buf, fil);

    if (written < 0)
        return -errno;

    return written;
}

void handle_open_flags(struct file *fd, int flags)
{
    if (flags & O_APPEND)
        fd->f_seek = fd->f_ino->i_size;
}

static inline mode_t get_current_umask(void)
{
    return get_current_process()->ctx.umask;
}

static struct file *try_to_open(struct file *base, const char *filename, int flags, mode_t mode)
{
    unsigned int open_flags = (flags & O_EXCL ? OPEN_FLAG_FAIL_IF_LINK : 0) |
                              (flags & O_NOFOLLOW ? OPEN_FLAG_FAIL_IF_LINK : 0) |
                              (flags & O_DIRECTORY ? OPEN_FLAG_MUST_BE_DIR : 0);
    struct file *ret = open_vfs_with_flags(base, filename, open_flags);

    if (ret)
    {
        /* Let's check for permissions */
        if (!file_can_access(ret, open_to_file_access_flags(flags)))
        {
            fd_put(ret);
            return errno = EACCES, nullptr;
        }

        if (ret->f_ino->i_type == VFS_TYPE_DIR)
        {
            if (flags & O_RDWR || flags & O_WRONLY || (flags & O_CREAT && !(flags & O_DIRECTORY)))
            {
                fd_put(ret);
                return errno = EISDIR, nullptr;
            }
        }

        if (flags & O_EXCL)
        {
            fd_put(ret);
            return errno = EEXIST, nullptr;
        }

        if (flags & O_TRUNC)
        {
            int st = ftruncate_vfs(0, ret);
            if (st < 0)
            {
                fd_put(ret);
                return nullptr;
            }
        }
    }

    if (!ret && errno == ENOENT && flags & O_CREAT)
        ret = creat_vfs(base->f_dentry, filename, mode & ~get_current_umask());

    return ret;
}

/* TODO: Add O_PATH */
/* TODO: Add O_SYNC */
#define VALID_OPEN_FLAGS                                                                       \
    (O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_DIRECTORY | O_EXCL | O_NOFOLLOW | O_NONBLOCK | \
     O_APPEND | O_CLOEXEC | O_LARGEFILE | O_TRUNC | O_NOCTTY | O_PATH)

int do_sys_open(const char *filename, int flags, mode_t mode, struct file *__rel)
{
    if (flags & ~VALID_OPEN_FLAGS)
    {
        // printk("Open(%s): Bad flags!\n", filename);
        // printk("Flag mask %o\n", flags & ~VALID_OPEN_FLAGS);
        return -EINVAL;
    }

    // printk("Open(%s)\n", filename);
    /* This function does all the open() work, open(2) and openat(2) use this */
    struct file *rel = __rel;
    struct file *base = get_fs_base(filename, rel);

    int fd_num = -1;

    /* Open/creat the file */
    struct file *file = try_to_open(base, filename, flags, mode);
    if (!file)
    {
        return -errno;
    }

    if (file->f_ino->i_fops->on_open)
    {
        int st = file->f_ino->i_fops->on_open(file);
        if (st < 0)
        {
            fd_put(file);
            return st;
        }
    }

    /* Allocate a file descriptor and a file description for the file */
    fd_num = open_with_vnode(file, flags);

    fd_put(file);

    return fd_num;
}

int sys_open(const char *ufilename, int flags, mode_t mode)
{
    const char *filename = strcpy_from_user(ufilename);
    if (!filename)
        return -errno;
    struct file *cwd = get_current_directory();
    /* TODO: Unify open and openat better */
    /* open(2) does relative opens using the current working directory */
    int fd = do_sys_open(filename, flags, mode, cwd);
    free((char *)filename);
    fd_put(cwd);
    return fd;
}

int sys_close(int fd)
{
    return file_close(fd);
}

int sys_dup(int fd)
{
    int st = 0;
    struct ioctx *ioctx = &get_current_process()->ctx;

    struct file *f = get_file_description(fd);
    if (!f)
        return -errno;

    int new_fd = alloc_fd(0);

    if (new_fd < 0)
    {
        st = new_fd;
        goto out_error;
    }

    ioctx->file_desc[new_fd] = f;

    /* We don't put the fd on success, because it's the reference the new fd holds */

    mutex_unlock(&ioctx->fdlock);

    return new_fd;
out_error:
    fd_put(f);
    return st;
}

int sys_dup2(int oldfd, int newfd)
{
    // printk("pid %d oldfd %d newfd %d\n", get_current_process()->pid, oldfd, newfd);
    struct process *current = get_current_process();
    struct ioctx *ioctx = &current->ctx;

    if (newfd < 0 || oldfd < 0)
        return -EINVAL;

    mutex_lock(&ioctx->fdlock);

    struct file *f = __get_file_description_unlocked(oldfd, current);
    if (!f)
    {
        newfd = -errno;
        goto out;
    }

    if ((unsigned int)newfd > ioctx->file_desc_entries)
    {
        int st = enlarge_file_descriptor_table(current, newfd + 1);
        if (st < 0)
        {
            fd_put(f);
            return st;
        }
    }

    if (oldfd == newfd)
        goto out;

    if (ioctx->file_desc[newfd])
        __file_close_unlocked(newfd, current);

    ioctx->file_desc[newfd] = ioctx->file_desc[oldfd];
    fd_set_cloexec(newfd, false, ioctx);
    fd_set_open(newfd, true, ioctx);

    // printk("refs: %lu\n", f->f_refcount);

    /* Note: To avoid fd_get/fd_put, we use the ref we get from
     * get_file_description as the ref for newfd. Therefore, we don't
     * fd_get and fd_put().
     */

out:
    mutex_unlock(&ioctx->fdlock);

    return newfd;
}

int sys_dup3(int oldfd, int newfd, int flags)
{
    struct process *current = get_current_process();
    struct ioctx *ioctx = &current->ctx;

    if (newfd < 0 || oldfd < 0)
        return -EINVAL;

    if (flags & ~O_CLOEXEC)
        return -EINVAL;

    mutex_lock(&ioctx->fdlock);

    struct file *f = __get_file_description_unlocked(oldfd, current);
    if (!f)
    {
        newfd = -errno;
        goto out;
    }

    if ((unsigned int)newfd > ioctx->file_desc_entries)
    {
        int st = enlarge_file_descriptor_table(current, newfd + 1);
        if (st < 0)
        {
            fd_put(f);
            return st;
        }
    }

    if (oldfd == newfd)
    {
        newfd = -EINVAL;
        goto out;
    }

    if (ioctx->file_desc[newfd])
        __file_close_unlocked(newfd, current);

    ioctx->file_desc[newfd] = ioctx->file_desc[oldfd];
    fd_set_cloexec(newfd, flags & O_CLOEXEC, ioctx);
    fd_set_open(newfd, true, ioctx);
    /* Note: To avoid fd_get/fd_put, we use the ref we get from
     * get_file_description as the ref for newfd. Therefore, we don't
     * fd_get and fd_put().
     */

out:
    mutex_unlock(&ioctx->fdlock);

    return newfd;
}

bool fd_may_access(struct file *f, unsigned int access)
{
    if (access == FILE_ACCESS_READ)
    {
        if (OPEN_FLAGS_ACCESS_MODE(f->f_flags) == O_WRONLY)
            return false;
    }
    else if (access == FILE_ACCESS_WRITE)
    {
        if (OPEN_FLAGS_ACCESS_MODE(f->f_flags) == O_RDONLY)
            return false;
    }

    return true;
}

ssize_t sys_readv(int fd, const struct iovec *vec, int veccnt)
{
    size_t read = 0;

    struct file *f = get_file_description(fd);
    if (!f)
        goto error;

    if (!vec)
    {
        errno = EINVAL;
        goto error;
    }

    if (veccnt == 0)
    {
        read = 0;
        goto out;
    }

    if (!fd_may_access(f, FILE_ACCESS_READ))
    {
        errno = EBADF;
        goto error;
    }

    for (int i = 0; i < veccnt; i++)
    {
        struct iovec v;
        if (copy_from_user(&v, vec++, sizeof(struct iovec)) < 0)
        {
            errno = EFAULT;
            goto error;
        }

        if (v.iov_len == 0)
            continue;
        ssize_t was_read = read_vfs(f->f_seek, v.iov_len, v.iov_base, f);
        if (was_read < 0)
        {
            goto out;
        }

        read += was_read;
        f->f_seek += was_read;

        if ((size_t)was_read != v.iov_len)
        {
            goto out;
        }
    }

out:
    fd_put(f);

    return read;
error:
    if (f)
        fd_put(f);
    return -errno;
}

ssize_t sys_writev(int fd, const struct iovec *vec, int veccnt)
{
    size_t written = 0;

    struct file *f = get_file_description(fd);
    if (!f)
        goto error;

    if (!vec)
    {
        errno = EINVAL;
        goto error;
    }

    if (veccnt == 0)
    {
        written = 0;
        goto out;
    }

    if (!fd_may_access(f, FILE_ACCESS_WRITE))
    {
        errno = EBADF;
        goto error;
    }

    for (int i = 0; i < veccnt; i++)
    {
        struct iovec v;
        if (copy_from_user(&v, vec++, sizeof(struct iovec)) < 0)
        {
            errno = EFAULT;
            goto error;
        }

        if (v.iov_len == 0)
            continue;

        if (f->f_flags & O_APPEND)
            f->f_seek = f->f_ino->i_size;

        size_t was_written = write_vfs(f->f_seek, v.iov_len, v.iov_base, f);

        written += was_written;
        f->f_seek += was_written;

        if (was_written != v.iov_len)
        {
            goto out;
        }
    }

out:
    fd_put(f);

    return written;
error:
    if (f)
        fd_put(f);
    return -errno;
}

ssize_t sys_preadv(int fd, const struct iovec *vec, int veccnt, off_t offset)
{
    size_t read = 0;

    struct file *f = get_file_description(fd);
    if (!f)
        goto error;

    if (!vec)
    {
        errno = EINVAL;
        goto error;
    }

    if (veccnt == 0)
    {
        read = 0;
        goto out;
    }

    if (!fd_may_access(f, FILE_ACCESS_READ))
    {
        errno = EBADF;
        goto error;
    }

    for (int i = 0; i < veccnt; i++)
    {
        struct iovec v;
        if (copy_from_user(&v, vec++, sizeof(struct iovec)) < 0)
        {
            errno = EFAULT;
            goto error;
        }

        if (v.iov_len == 0)
            continue;
        ssize_t was_read = read_vfs(offset, v.iov_len, v.iov_base, f);

        if (was_read < 0)
        {
            goto out;
        }

        read += was_read;
        offset += was_read;

        if ((size_t)was_read != v.iov_len)
        {
            goto out;
        }
    }

out:
    fd_put(f);

    return read;
error:
    if (f)
        fd_put(f);
    return -errno;
}

ssize_t sys_pwritev(int fd, const struct iovec *vec, int veccnt, off_t offset)
{
    size_t written = 0;

    struct file *f = get_file_description(fd);
    if (!f)
        goto error;

    if (!vec)
    {
        errno = EINVAL;
        goto error;
    }

    if (veccnt == 0)
    {
        written = 0;
        goto out;
    }

    if (!fd_may_access(f, FILE_ACCESS_WRITE))
    {
        errno = EBADF;
        goto error;
    }

    for (int i = 0; i < veccnt; i++)
    {
        struct iovec v;
        if (copy_from_user(&v, vec++, sizeof(struct iovec)) < 0)
        {
            errno = EFAULT;
            goto error;
        }

        if (v.iov_len == 0)
            continue;
        size_t was_written = write_vfs(offset, v.iov_len, v.iov_base, f);

        written += was_written;
        offset += was_written;

        if (was_written != v.iov_len)
        {
            goto out;
        }
    }

out:
    fd_put(f);

    return written;
error:
    if (f)
        fd_put(f);
    return -errno;
}

unsigned int putdir(struct dirent *buf, struct dirent *ubuf, unsigned int count);

int sys_getdents(int fd, struct dirent *dirp, unsigned int count)
{
    int ret = 0;
    if (!count)
        return -EINVAL;

    auto_file f = get_file_description(fd);
    if (!f)
    {
        return -errno;
    }

    auto fil = f.get_file();

    struct getdents_ret ret_buf = {};
    ret = getdents_vfs(count, putdir, dirp, fil->f_seek, &ret_buf, fil);
    if (ret < 0)
    {
        return -errno;
    }

    fil->f_seek = ret_buf.new_off;

    ret = ret_buf.read;
    return ret;
}

int sys_ioctl(int fd, int request, char *argp)
{
    struct file *f = get_file_description(fd);
    if (!f)
    {
        return -errno;
    }

    int ret = ioctl_vfs(request, argp, f);

    fd_put(f);
    return ret;
}

int sys_truncate(const char *path, off_t length)
{
    return -ENOSYS;
}

int sys_ftruncate(int fd, off_t length)
{
    struct file *f = get_file_description(fd);
    if (!f)
    {
        return -errno;
    }

    int ret = 0;

    if (!fd_may_access(f, FILE_ACCESS_WRITE))
    {
        ret = -EBADF;
        goto out;
    }

    ret = ftruncate_vfs(length, f);

out:
    fd_put(f);
    return ret;
}

int sys_fallocate(int fd, int mode, off_t offset, off_t len)
{
    struct file *f = get_file_description(fd);
    if (!f)
    {
        return -errno;
    }

    int ret = fallocate_vfs(mode, offset, len, f);

    fd_put(f);
    return ret;
}

off_t sys_lseek(int fd, off_t offset, int whence)
{
    /* TODO: Fix O_APPEND behavior */
    off_t ret = 0;
    struct file *f = get_file_description(fd);
    if (!f)
        return -errno;

    /* TODO: Add a way for inodes to tell they don't support seeking */
    if (f->f_ino->i_type == VFS_TYPE_FIFO || f->f_ino->i_flags & INODE_FLAG_NO_SEEK)
    {
        ret = -ESPIPE;
        goto out;
    }

    if (whence == SEEK_CUR)
        ret = __sync_add_and_fetch(&f->f_seek, offset);
    else if (whence == SEEK_SET)
        ret = f->f_seek = offset;
    else if (whence == SEEK_END)
        ret = f->f_seek = f->f_ino->i_size + offset;
    else
    {
        ret = -EINVAL;
    }

out:
    fd_put(f);
    return ret;
}

int sys_mount(const char *usource, const char *utarget, const char *ufilesystemtype,
              unsigned long mountflags, const void *data)
{
    const char *source = nullptr;
    const char *target = nullptr;
    struct file *block_file = nullptr;
    const char *filesystemtype = nullptr;
    int ret = 0;
    fs_mount *fs = nullptr;
    struct blockdev *d = nullptr;
    struct inode *node = nullptr;
    char *str = nullptr;

    source = strcpy_from_user(usource);
    if (!source)
    {
        ret = -errno;
        goto out;
    }

    target = strcpy_from_user(utarget);
    if (!target)
    {
        ret = -errno;
        goto out;
    }

    filesystemtype = strcpy_from_user(ufilesystemtype);
    if (!filesystemtype)
    {
        ret = -errno;
        goto out;
    }
    /* Find the 'filesystemtype's handler */
    fs = fs_mount_get(filesystemtype);
    if (!fs)
    {
        ret = -ENODEV;
        goto out;
    }

    if (fs->flags & FS_MOUNT_PSEUDO_FS)
    {
        // Pseudo fs's dont have a backing block device
        block_file = nullptr;
        d = nullptr;
    }
    else
    {
        block_file = open_vfs(get_fs_root(), source);
        if (!block_file)
        {
            ret = -ENOENT;
            goto out;
        }

        if (!S_ISBLK(block_file->f_ino->i_mode))
        {
            ret = -ENOTBLK;
            goto out;
        }

        d = blkdev_get_dev(block_file);
    }

    if (!(node = fs->mount(d)))
    {
        ret = -EINVAL;
        goto out;
    }

    str = strdup(target);
    if (!str)
    {
        ret = -ENOMEM;
        goto out;
    }

    if (mount_fs(node, str) < 0)
    {
        free(str);
    }

out:
    if (block_file)
        fd_put(block_file);
    if (source)
        free((void *)source);
    if (target)
        free((void *)target);
    if (filesystemtype)
        free((void *)filesystemtype);
    return ret;
}

int sys_pipe(int *upipefd)
{
    int pipefd[2] = {-1, -1};
    int st = 0;

    /* Create the pipe */
    struct file *read_end, *write_end;

    if (pipe_create(&read_end, &write_end) < 0)
    {
        return -errno;
    }

    pipefd[0] = open_with_vnode(read_end, O_RDONLY);
    if (pipefd[0] < 0)
    {
        st = -errno;
        goto error;
    }

    pipefd[1] = open_with_vnode(write_end, O_WRONLY);
    if (pipefd[1] < 0)
    {
        st = -errno;
        goto error;
    }

    if (copy_to_user(upipefd, pipefd, sizeof(int) * 2) < 0)
    {
        st = -EFAULT;
        goto error;
    }

    fd_put(read_end);
    fd_put(write_end);

    return 0;
error:
    fd_put(read_end);
    fd_put(write_end);

    if (pipefd[0] != -1)
        file_close(pipefd[0]);
    if (pipefd[1] != -1)
        file_close(pipefd[1]);

    return -st;
}

int do_dupfd(struct file *f, int fdbase, bool cloexec)
{
    int new_fd = alloc_fd(fdbase);
    if (new_fd < 0)
        return new_fd;

    struct ioctx *ioctx = &get_current_process()->ctx;
    ioctx->file_desc[new_fd] = f;

    fd_get(f);

    fd_set_cloexec(new_fd, cloexec, ioctx);

    mutex_unlock(&ioctx->fdlock);

    return new_fd;
}

int fcntl_f_getfd(int fd, struct ioctx *ctx)
{
    mutex_lock(&ctx->fdlock);

    if (!validate_fd_number(fd, ctx))
    {
        mutex_unlock(&ctx->fdlock);
        return -EBADF;
    }

    int st = fd_is_cloexec(fd, ctx) ? FD_CLOEXEC : 0;

    mutex_unlock(&ctx->fdlock);
    return st;
}

int fcntl_f_setfd(int fd, unsigned long arg, struct ioctx *ctx)
{
    mutex_lock(&ctx->fdlock);

    if (!validate_fd_number(fd, ctx))
    {
        mutex_unlock(&ctx->fdlock);
        return -EBADF;
    }

    bool wants_cloexec = arg & FD_CLOEXEC;

    fd_set_cloexec(fd, wants_cloexec, ctx);

    mutex_unlock(&ctx->fdlock);

    return 0;
}

int fcntl_f_getfl(int fd, struct ioctx *ctx)
{
    bool is_cloexec;

    mutex_lock(&ctx->fdlock);

    if (!validate_fd_number(fd, ctx))
    {
        mutex_unlock(&ctx->fdlock);
        return -EBADF;
    }

    is_cloexec = fd_is_cloexec(fd, ctx);

    mutex_unlock(&ctx->fdlock);

    struct file *f = get_file_description(fd);
    if (!f)
        return -errno;
    unsigned int result = f->f_flags | (is_cloexec ? O_CLOEXEC : 0);

    fd_put(f);

    return result;
}

#define SETFL_MASK (O_APPEND | O_ASYNC | O_DIRECT | O_NOATIME | O_NONBLOCK)

int fcntl_f_setfl(int fd, struct ioctx *ctx, unsigned long arg)
{
    struct file *f = get_file_description(fd);
    if (!f)
        return -errno;

    /* TODO: Some flags, like O_ASYNC are not that simple to handle... */
    arg &= (O_APPEND | O_ASYNC | O_DIRECT | O_NOATIME | O_NONBLOCK);

    f->f_flags = arg | (f->f_flags & ~SETFL_MASK);

    fd_put(f);

    return 0;
}

int sys_fcntl(int fd, int cmd, unsigned long arg)
{
    /* TODO: Get new flags for file descriptors. The use of O_* is confusing since
     * those only apply on open calls. For example, fcntl uses FD_*. */
    struct file *f = nullptr;
    struct ioctx *ctx = &get_current_process()->ctx;

    int ret = 0;
    switch (cmd)
    {
    case F_DUPFD: {
        f = get_file_description(fd);
        if (!f)
            return -errno;

        ret = do_dupfd(f, (int)arg, false);
        break;
    }

    case F_DUPFD_CLOEXEC: {
        f = get_file_description(fd);
        if (!f)
            return -errno;

        ret = do_dupfd(f, (int)arg, true);
        break;
    }

    case F_GETFD: {
        return fcntl_f_getfd(fd, ctx);
    }

    case F_SETFD: {
        return fcntl_f_setfd(fd, arg, ctx);
    }

    case F_GETFL:
        return fcntl_f_getfl(fd, ctx);
    case F_SETFL:
        return fcntl_f_setfl(fd, ctx, arg);

    default:
        ret = -EINVAL;
        break;
    }

    if (f)
        fd_put(f);
    return ret;
}

#define STAT_FLAG_LSTAT (1 << 0)

int do_sys_stat(const char *pathname, struct stat *buf, int flags, struct file *rel)
{
    unsigned int open_flags = (flags & STAT_FLAG_LSTAT ? OPEN_FLAG_NOFOLLOW : 0);
    struct file *base = get_fs_base(pathname, rel);
    struct file *stat_node = open_vfs_with_flags(base, pathname, open_flags);
    if (!stat_node)
        return -errno; /* Don't set errno, as we don't know if it was actually a ENOENT */

    int st = stat_vfs(buf, stat_node);
    fd_put(stat_node);
    return st < 0 ? -errno : st;
}

int sys_stat(const char *upathname, struct stat *ubuf)
{
    const char *pathname = strcpy_from_user(upathname);
    if (!pathname)
        return -errno;

    struct stat buf = {};
    struct file *curr = get_current_directory();

    int st = do_sys_stat(pathname, &buf, 0, curr);

    fd_put(curr);

    if (copy_to_user(ubuf, &buf, sizeof(buf)) < 0)
    {
        st = -errno;
    }

    free((void *)pathname);
    return st;
}

int sys_lstat(const char *upathname, struct stat *ubuf)
{
    const char *pathname = strcpy_from_user(upathname);
    if (!pathname)
        return -errno;

    struct stat buf = {};
    struct file *curr = get_current_directory();

    int st = do_sys_stat(pathname, &buf, STAT_FLAG_LSTAT, curr);

    fd_put(curr);

    if (copy_to_user(ubuf, &buf, sizeof(buf)) < 0)
    {
        st = -errno;
    }

    free((void *)pathname);
    return st;
}

int sys_fstat(int fd, struct stat *ubuf)
{
    auto_file f = get_file_description(fd);
    if (!f)
    {
        return -errno;
    }

    struct stat buf = {};

    if (stat_vfs(&buf, f.get_file()) < 0)
    {
        return -errno;
    }

    if (copy_to_user(ubuf, &buf, sizeof(buf)) < 0)
    {
        return -EFAULT;
    }

    return 0;
}

int sys_chdir(const char *upath)
{
    const char *path = strcpy_from_user(upath);
    if (!path)
        return -errno;

    int st = 0;
    struct file *curr = get_current_directory();
    struct file *base = get_fs_base(path, curr);
    struct file *dir = open_vfs(base, path);
    struct file *f, *old;
    struct process *current;
    struct ioctx *ctx;

    fd_put(curr);

    if (!dir)
    {
        st = -errno;
        goto out;
    }

    if (!(dir->f_ino->i_type & VFS_TYPE_DIR))
    {
        st = -ENOTDIR;
        goto close_file;
    }

    f = dir;

    current = get_current_process();
    ctx = &current->ctx;
    spin_lock(&ctx->cwd_lock);

    old = ctx->cwd;
    ctx->cwd = f;

    spin_unlock(&ctx->cwd_lock);

    /* We've swapped ptrs atomically and now we're dropping the cwd reference.
     * Note that any current users of the cwd are using it properly.
     */
    fd_put(old);
    goto out;
close_file:
    if (dir)
        fd_put(dir);
out:
    if (path)
        free((void *)path);
    return st;
}

int sys_fchdir(int fildes)
{
    struct file *f = get_file_description(fildes);
    if (!f)
        return -errno;

    struct file *node = f;
    if (!(node->f_ino->i_type & VFS_TYPE_DIR))
    {
        fd_put(f);
        return -ENOTDIR;
    }

    struct process *current = get_current_process();
    struct ioctx *ctx = &current->ctx;
    spin_lock(&ctx->cwd_lock);

    struct file *old = ctx->cwd;
    ctx->cwd = f;

    spin_unlock(&ctx->cwd_lock);

    /* We've swapped ptrs atomically and now we're dropping the cwd reference.
     * Note that any current users of the cwd are using it properly.
     */
    fd_put(old);

    return 0;
}

int sys_getcwd(char *path, size_t size)
{
    if (size == 0 && path != nullptr)
        return -EINVAL;

    struct file *cwd = get_current_directory();
    char *name = dentry_to_file_name(cwd->f_dentry);

    fd_put(cwd);

    if (!name)
    {
        return -errno;
    }

    if (strlen(name) + 1 > size)
    {
        free(name);
        return -ERANGE;
    }

    if (copy_to_user(path, name, strlen(name) + 1) < 0)
    {
        free(name);
        return -errno;
    }

    return strlen(name);
}

struct file *get_dirfd_file(int dirfd)
{
    struct file *dirfd_desc = nullptr;
    if (dirfd != AT_FDCWD)
    {
        dirfd_desc = get_file_description(dirfd);
        if (!dirfd_desc)
            return nullptr;
    }
    else
        dirfd_desc = get_current_directory();

    return dirfd_desc;
}

int sys_openat(int dirfd, const char *upath, int flags, mode_t mode)
{
    struct file *dirfd_desc = nullptr;

    dirfd_desc = get_dirfd_file(dirfd);
    if (!dirfd_desc)
        return -errno;

    const char *path = strcpy_from_user(upath);
    if (!path)
    {
        if (dirfd_desc)
            fd_put(dirfd_desc);
        return -errno;
    }

    int fd = do_sys_open(path, flags, mode, dirfd_desc);

    free((char *)path);
    if (dirfd_desc)
        fd_put(dirfd_desc);

    return fd;
}

int sys_fstatat(int dirfd, const char *upathname, struct stat *ubuf, int flags)
{
    const char *pathname = strcpy_from_user(upathname);
    if (!pathname)
        return -errno;
    struct stat buf = {};
    struct file *dir;
    int st = 0;
    struct file *dirfd_desc = get_dirfd_file(dirfd);
    if (!dirfd_desc)
    {
        st = -errno;
        goto out;
    }

    dir = dirfd_desc;

    st = do_sys_stat(pathname, &buf, flags, dir);

    if (copy_to_user(ubuf, &buf, sizeof(buf)) < 0)
    {
        st = -errno;
        goto out;
    }
out:
    if (dirfd_desc)
        fd_put(dirfd_desc);
    free((void *)pathname);
    return st;
}

int sys_fmount(int fd, const char *upath)
{
    struct file *f = get_file_description(fd);
    if (!f)
        return -errno;

    const char *path = strcpy_from_user(upath);
    if (!path)
    {
        fd_put(f);
        return -errno;
    }

    int st = mount_fs(f->f_ino, path);

    free((void *)path);
    fd_put(f);
    return st;
}

void file_do_cloexec(struct ioctx *ctx)
{
    mutex_lock(&ctx->fdlock);
    struct file **fd = ctx->file_desc;

    for (unsigned int i = 0; i < ctx->file_desc_entries; i++)
    {
        if (!fd[i])
            continue;
        if (fd_is_cloexec(i, ctx))
        {
            /* Close the file */
            __file_close_unlocked(i, get_current_process());
        }
    }

    mutex_unlock(&ctx->fdlock);
}

int open_with_vnode(struct file *node, int flags)
{
    /* This function does all the open() work, open(2) and openat(2) use this */
    struct ioctx *ioctx = &get_current_process()->ctx;

    int fd_num = -1;
    /* Allocate a file descriptor and a file description for the file */
    fd_num = file_alloc(node, ioctx);
    if (fd_num < 0)
    {
        mutex_unlock(&ioctx->fdlock);
        return -errno;
    }

    node->f_seek = 0;
    node->f_flags = flags;
    handle_open_flags(node, flags);
    bool cloexec = flags & O_CLOEXEC;
    fd_set_cloexec(fd_num, cloexec, ioctx);

    mutex_unlock(&ioctx->fdlock);
    return fd_num;
}

int sys_faccessat(int dirfd, const char *upath, int amode, int flags)
{
    // TODO: Implement flags, we're doing the check wrong(it should be with ruid
    // instead of euid by default)
    user_string path;
    auto_file f;

    if (int st = f.from_dirfd(dirfd); st < 0)
        return st;

    if (auto res = path.from_user(upath); res.has_error())
        return -EFAULT;

    auto_file file = open_vfs(f.get_file(), path.data());

    unsigned int mask = ((amode & R_OK) ? FILE_ACCESS_READ : 0) |
                        ((amode & X_OK) ? FILE_ACCESS_EXECUTE : 0) |
                        ((amode & W_OK) ? FILE_ACCESS_WRITE : 0);
    if (!file)
    {
        return -errno;
    }

    if (!file_can_access(file.get_file(), mask))
    {
        return -EACCES;
    }

    return 0;
}

int sys_access(const char *path, int amode)
{
    return sys_faccessat(AT_FDCWD, path, amode, 0);
}

int do_sys_mkdir(const char *path, mode_t mode, struct file *dir)
{
    struct file *base = get_fs_base(path, dir);

    struct file *i = mkdir_vfs(path, mode & ~get_current_umask(), base->f_dentry);
    if (!i)
        return -errno;

    fd_put(i);
    return 0;
}

int sys_mkdirat(int dirfd, const char *upath, mode_t mode)
{
    struct file *dir;
    struct file *dirfd_desc = nullptr;

    dirfd_desc = get_dirfd_file(dirfd);
    if (!dirfd_desc)
    {
        return -errno;
    }

    dir = dirfd_desc;

    if (!(dir->f_ino->i_type & VFS_TYPE_DIR))
    {
        if (dirfd_desc)
            fd_put(dirfd_desc);
        return -ENOTDIR;
    }

    char *path = strcpy_from_user(upath);
    if (!path)
    {
        if (dirfd_desc)
            fd_put(dirfd_desc);
        return -errno;
    }

    int ret = do_sys_mkdir(path, mode, dir);

    free((char *)path);
    if (dirfd_desc)
        fd_put(dirfd_desc);

    return ret;
}

int sys_mkdir(const char *upath, mode_t mode)
{
    return sys_mkdirat(AT_FDCWD, upath, mode);
}

int do_sys_mknodat(const char *path, mode_t mode, dev_t dev, struct file *dir)
{
    struct file *base = get_fs_base(path, dir);

    struct file *i = mknod_vfs(path, mode & ~get_current_umask(), dev, base->f_dentry);
    if (!i)
        return -errno;

    fd_put(i);
    return 0;
}

int sys_mknodat(int dirfd, const char *upath, mode_t mode, dev_t dev)
{
    struct file *dir;
    struct file *dirfd_desc = nullptr;

    dirfd_desc = get_dirfd_file(dirfd);
    if (!dirfd_desc)
    {
        return -errno;
    }

    dir = dirfd_desc;

    if (!(dir->f_ino->i_type & VFS_TYPE_DIR))
    {
        if (dirfd_desc)
            fd_put(dirfd_desc);
        return -ENOTDIR;
    }

    char *path = strcpy_from_user(upath);
    if (!path)
    {
        if (dirfd_desc)
            fd_put(dirfd_desc);
        return -errno;
    }

    int ret = do_sys_mknodat(path, mode, dev, dir);

    free((char *)path);
    if (dirfd_desc)
        fd_put(dirfd_desc);

    return ret;
}

int sys_mknod(const char *pathname, mode_t mode, dev_t dev)
{
    return sys_mknodat(AT_FDCWD, pathname, mode, dev);
}

ssize_t sys_readlinkat(int dirfd, const char *upathname, char *ubuf, size_t bufsiz)
{
    if ((ssize_t)bufsiz < 0)
        return -EINVAL;
    ssize_t st = 0;
    char *pathname = strcpy_from_user(upathname);
    if (!pathname)
        return -errno;

    struct file *f;
    char *buf;
    size_t buf_len, to_copy;

    struct file *base = get_dirfd_file(dirfd);
    if (!base)
    {
        st = -errno;
        goto out;
    }

    f = open_vfs_with_flags(base, pathname, OPEN_FLAG_NOFOLLOW);
    if (!f)
    {
        st = -errno;
        goto out;
    }

    buf = readlink_vfs(f);
    if (!buf)
    {
        st = -errno;
        goto out1;
    }

    buf_len = strlen(buf);
    to_copy = buf_len < bufsiz ? buf_len : bufsiz;

    st = copy_to_user(ubuf, buf, to_copy);

    /* If the copy succeeded, set return to to_copy(it would be zero otherwise) */
    if (st == 0)
        st = to_copy;

    free(buf);
out1:
    fd_put(f);
out:
    free(pathname);
    if (base)
        fd_put(base);
    return st;
}

ssize_t sys_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    return sys_readlinkat(AT_FDCWD, pathname, buf, bufsiz);
}

mode_t sys_umask(mode_t mask)
{
    struct process *current = get_current_process();
    mode_t old = current->ctx.umask;
    current->ctx.umask = mask & 0777;

    return old;
}

int sys_chmod(const char *pathname, mode_t mode)
{
    return -ENOSYS;
}
int sys_fchmod(int fd, mode_t mode)
{
    return -ENOSYS;
}
int sys_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{
    return -ENOSYS;
}
int sys_chown(const char *pathname, uid_t owner, gid_t group)
{
    return -ENOSYS;
}
int sys_fchown(int fd, uid_t owner, gid_t group)
{
    return -ENOSYS;
}
int sys_lchown(const char *pathname, uid_t owner, gid_t group)
{
    return -ENOSYS;
}
int sys_fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
{
    return -ENOSYS;
}

int sys_utimensat(int dirfd, const char *pathname, const struct timespec *times, int flags)
{
    return -ENOSYS;
}

/**
 * @brief Retrieve statistics about a specific file's filesystem
 *
 * @param f Pointer to the file
 * @param buf Pointer to the statfs buffer (kernel pointer)
 * @return 0 on success, else negative error code
 */
int kernel_statfs(file *f, struct statfs *buf)
{
    auto ino = f->f_ino;
    auto sb = ino->i_sb;

    // Not supported
    if (!sb || !sb->statfs)
        return -ENOSYS;

    // Prevent any accidental leak by zeroing it all explicitly
    memset(buf, 0, sizeof(*buf));

    // Provide safe defaults for statfs
    // All these are safely overridable by filesystem code
    buf->f_namelen = NAME_MAX;
    buf->f_frsize = 0;

    // Unsure about this, but this is not going to be a security hazard anyway
    buf->f_fsid.__val[0] = (int)sb->s_devnr;
    buf->f_fsid.__val[1] = (int)(sb->s_devnr >> 32);

    return sb->statfs(buf, sb);
}

int core_statfs(file *f, struct statfs *ubuf)
{
    struct statfs buf;

    if (int st = kernel_statfs(f, &buf); st < 0)
        return st;

    return copy_to_user(ubuf, &buf, sizeof(buf));
}

int sys_statfs(const char *upath, struct statfs *ubuf)
{
    user_string path;
    if (auto ex = path.from_user(upath); ex.has_error())
        return ex.error();

    auto_file cwd = get_current_directory();
    auto_file f = open_vfs(cwd.get_file(), path.data());
    if (!f)
        return -errno;

    return core_statfs(f.get_file(), ubuf);
}

int sys_fstatfs(int fd, struct statfs *ubuf)
{
    auto_file f = get_file_description(fd);

    if (!f)
        return -errno;

    return core_statfs(f.get_file(), ubuf);
}
