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
#include <onyx/mm/slab.h>
#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/user.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

bool is_absolute_filename(const char *file)
{
    return *file == '/';
}

struct file *get_fs_base(const char *file, struct file *rel_base)
{
    return is_absolute_filename(file) ? get_fs_root() : rel_base;
}

struct file *get_current_directory()
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
    __atomic_add_fetch(&fd->f_refcount, 1, __ATOMIC_ACQUIRE);
}

void fd_put(struct file *fd)
{
    if (__atomic_sub_fetch(&fd->f_refcount, 1, __ATOMIC_RELEASE) == 0)
    {
        if (fd->f_ino->i_fops->release)
            fd->f_ino->i_fops->release(fd);

        close_vfs(fd->f_ino);
        // printk("file %s dentry refs %lu\n", fd->f_dentry->d_name, fd->f_dentry->d_ref);
        dentry_put(fd->f_dentry);
        file_free(fd);
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

    if ((unsigned int) fd >= ctx->file_desc_entries)
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

    spin_lock(&ctx->fdlock);

    struct file *f = __get_file_description_unlocked(fd, p);

    spin_unlock(&ctx->fdlock);

    return f;
}

expected<file *, int> __file_close_unlocked(int fd, struct process *p)
{
    // printk("pid %d close %d\n", get_current_process()->pid, fd);
    struct ioctx *ctx = &p->ctx;

    if (!validate_fd_number(fd, ctx))
        return unexpected<int>{-EBADF};

    struct file *f = ctx->file_desc[fd];

    /* Set the entry to nullptr */
    /* TODO: Shrink the fd table? */
    ctx->file_desc[fd] = nullptr;
    fd_close_bit(fd, ctx);

    return f;
}

int __file_close(int fd, struct process *p)
{
    struct ioctx *ctx = &p->ctx;

    spin_lock(&ctx->fdlock);

    auto ex = __file_close_unlocked(fd, p);

    spin_unlock(&ctx->fdlock);

    if (ex.has_error())
        return ex.error();

    fd_put(ex.value());

    return 0;
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
    scoped_lock g{ctx->fdlock};

    process->ctx.file_desc = (file **) malloc(ctx->file_desc_entries * sizeof(void *));
    process->ctx.file_desc_entries = ctx->file_desc_entries;
    if (!process->ctx.file_desc)
    {
        return -ENOMEM;
    }

    process->ctx.cloexec_fds = (unsigned long *) malloc(ctx->file_desc_entries / 8);
    if (!process->ctx.cloexec_fds)
    {
        free(process->ctx.file_desc);
        return -ENOMEM;
    }

    process->ctx.open_fds = (unsigned long *) malloc(ctx->file_desc_entries / 8);
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
    process->ctx.file_desc = (file **) zalloc(FILE_DESCRIPTOR_GROW_NR * sizeof(void *));
    if (!process->ctx.file_desc)
        return -ENOMEM;

    process->ctx.file_desc_entries = FILE_DESCRIPTOR_GROW_NR;

    process->ctx.cloexec_fds = (unsigned long *) zalloc(FILE_DESCRIPTOR_GROW_NR / 8);
    if (!process->ctx.cloexec_fds)
    {
        free(process->ctx.file_desc);
        return -ENOMEM;
    }

    process->ctx.open_fds = (unsigned long *) zalloc(FILE_DESCRIPTOR_GROW_NR / 8);
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

    if (new_size > INT_MAX || new_size >= process->get_rlimit(RLIMIT_NOFILE).rlim_cur)
        return -EBADF;

    unsigned int new_nr_fds = new_size;

    struct file **table = (file **) malloc(new_nr_fds * sizeof(void *));
    unsigned long *cloexec_fds = (unsigned long *) malloc(FD_ENTRIES_TO_FDSET_SIZE(new_nr_fds));
    /* We use zalloc here to implicitly zero free fds */
    unsigned long *open_fds = (unsigned long *) zalloc(FD_ENTRIES_TO_FDSET_SIZE(new_nr_fds));
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
    process->ctx.file_desc_entries = new_nr_fds;

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
    spin_lock(&ctx->fdlock);

    for (unsigned int i = 0; i < ctx->file_desc_entries; i++)
    {
        if (!fd_is_open(i, ctx))
            continue;

        fd_put(table[i]);
    }

    free(table);

    ctx->file_desc = nullptr;
    ctx->file_desc_entries = 0;

    spin_unlock(&ctx->fdlock);
}

int alloc_fd(int fdbase)
{
    auto current = get_current_process();

    if (fdbase < 0 || fdbase == INT_MAX ||
        (unsigned int) fdbase >= current->get_rlimit(RLIMIT_NOFILE).rlim_cur)
        return -EBADF;

    struct ioctx *ioctx = &current->ctx;
    scoped_lock g{ioctx->fdlock};

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
                    if (current->get_rlimit(RLIMIT_NOFILE).rlim_cur < (unsigned long) fd)
                        return -EMFILE;
                    /* Found a free fd that we can use, let's mark it used and return it */
                    ioctx->open_fds[i] |= (1UL << j);
                    /* And don't forget to reset the cloexec flag! */
                    fd_set_cloexec(fd, false, ioctx);
                    g.keep_locked();
                    return fd;
                }
            }
        }

        /* TODO: Make it so we can enlarge it directly to the size we want */
        int new_entries = ioctx->file_desc_entries + FILE_DESCRIPTOR_GROW_NR;
        if (enlarge_file_descriptor_table(current, new_entries) < 0)
        {
            return -ENOMEM;
        }
    }
}

int file_alloc(struct file *f, struct ioctx *ioctx)
{
    assert(f != nullptr);
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

    ssize_t size = read_vfs(fil->f_seek, count, (char *) buf, fil);
    if (size < 0)
    {
        return size;
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

    auto written = write_vfs(fil->f_seek, count, (void *) buf, fil);

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

    ssize_t size = read_vfs(offset, count, (char *) buf, fil);
    if (size < 0)
    {
        return size;
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

    ssize_t written = write_vfs(offset, count, (void *) buf, fil);

    if (written < 0)
        return -errno;

    return written;
}

void handle_open_flags(struct file *fd, int flags)
{
    if (flags & O_APPEND)
        fd->f_seek = fd->f_ino->i_size;
}

static inline mode_t get_current_umask()
{
    return get_current_process()->ctx.umask;
}

bool may_noatime(file *f)
{
    creds_guard g;
    return g.get()->euid == 0 || f->f_ino->i_uid == g.get()->euid;
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

        // O_NOATIME can only be used when the euid of the process = owner of file, or
        // when we're privileged (root).
        if (flags & O_NOATIME)
        {
            if (!may_noatime(ret))
                return errno = EPERM, nullptr;
        }

        if (S_ISDIR(ret->f_ino->i_mode))
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
     O_APPEND | O_CLOEXEC | O_LARGEFILE | O_TRUNC | O_NOCTTY | O_PATH | O_NOATIME)

int do_sys_open(const char *filename, int flags, mode_t mode, struct file *__rel)
{
    if (flags & ~VALID_OPEN_FLAGS)
    {
        printk("Open(%s): Bad flags!\n", filename);
        printk("Flag mask %o\n", flags & ~VALID_OPEN_FLAGS);
        return -EINVAL;
    }

    // printk("Open(%s, %x)\n", filename, flags);
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
    free((char *) filename);
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

    spin_unlock(&ioctx->fdlock);

    return new_fd;
out_error:
    fd_put(f);
    return st;
}

#define DUP23_DUP3 (1 << 0)

int sys_dup23_internal(int oldfd, int newfd, int dupflags, unsigned int flags)
{
    // printk("pid %d oldfd %d newfd %d\n", get_current_process()->pid, oldfd, newfd);
    struct process *current = get_current_process();
    struct ioctx *ioctx = &current->ctx;

    if (newfd < 0 || oldfd < 0)
        return -EBADF;

    scoped_lock g{ioctx->fdlock};

    struct file *newf_old = nullptr;

    struct file *f = __get_file_description_unlocked(oldfd, current);
    if (!f)
    {
        newfd = -errno;
        goto out;
    }

    if ((unsigned int) newfd > ioctx->file_desc_entries)
    {
        int st = enlarge_file_descriptor_table(current, (unsigned int) newfd + 1);
        if (st < 0)
        {
            fd_put(f);
            return st;
        }
    }

    if (oldfd == newfd)
    {
        fd_put(f);
        return flags & DUP23_DUP3 ? -EINVAL : 0;
    }

    if (ioctx->file_desc[newfd])
    {
        auto ex = __file_close_unlocked(newfd, current);
        if (ex.has_error())
        {
            fd_put(f);
            return ex.error();
        }

        newf_old = ex.value();
    }

    ioctx->file_desc[newfd] = f;
    fd_set_cloexec(newfd, dupflags & O_CLOEXEC, ioctx);
    fd_set_open(newfd, true, ioctx);

    // printk("refs: %lu\n", f->f_refcount);

    /* Note: To avoid fd_get/fd_put, we use the ref we get from
     * get_file_description as the ref for newfd. Therefore, we don't
     * fd_get and fd_put().
     */

    g.unlock();

    if (newf_old)
        fd_put(newf_old);

out:
    return newfd;
}

int sys_dup2(int oldfd, int newfd)
{
    return sys_dup23_internal(oldfd, newfd, 0, 0);
}

int sys_dup3(int oldfd, int newfd, int flags)
{
    if (flags & ~O_CLOEXEC)
        return -EINVAL;

    return sys_dup23_internal(oldfd, newfd, flags, DUP23_DUP3);
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
    ssize_t was_read = 0;

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
        was_read = read_vfs(f->f_seek, v.iov_len, v.iov_base, f);
        if (was_read < 0)
        {
            goto error;
        }

        read += was_read;
        f->f_seek += was_read;

        if ((size_t) was_read != v.iov_len)
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
    return was_read;
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
    ssize_t was_read = 0;

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
        was_read = read_vfs(offset, v.iov_len, v.iov_base, f);

        if (was_read < 0)
        {
            goto error;
        }

        read += was_read;
        offset += was_read;

        if ((size_t) was_read != v.iov_len)
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
    return was_read;
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
        free((void *) source);
    if (target)
        free((void *) target);
    if (filesystemtype)
        free((void *) filesystemtype);
    return ret;
}

int do_dupfd(struct file *f, int fdbase, bool cloexec)
{
    if (fdbase < 0)
        return -EBADF;
    int new_fd = alloc_fd(fdbase);
    if (new_fd < 0)
        return new_fd;

    struct ioctx *ioctx = &get_current_process()->ctx;
    ioctx->file_desc[new_fd] = f;

    fd_get(f);

    fd_set_cloexec(new_fd, cloexec, ioctx);

    spin_unlock(&ioctx->fdlock);

    return new_fd;
}

int fcntl_f_getfd(int fd, struct ioctx *ctx)
{
    spin_lock(&ctx->fdlock);

    if (!validate_fd_number(fd, ctx))
    {
        spin_unlock(&ctx->fdlock);
        return -EBADF;
    }

    int st = fd_is_cloexec(fd, ctx) ? FD_CLOEXEC : 0;

    spin_unlock(&ctx->fdlock);
    return st;
}

int fcntl_f_setfd(int fd, unsigned long arg, struct ioctx *ctx)
{
    spin_lock(&ctx->fdlock);

    if (!validate_fd_number(fd, ctx))
    {
        spin_unlock(&ctx->fdlock);
        return -EBADF;
    }

    bool wants_cloexec = arg & FD_CLOEXEC;

    fd_set_cloexec(fd, wants_cloexec, ctx);

    spin_unlock(&ctx->fdlock);

    return 0;
}

int fcntl_f_getfl(int fd, struct ioctx *ctx)
{
    bool is_cloexec;

    spin_lock(&ctx->fdlock);

    if (!validate_fd_number(fd, ctx))
    {
        spin_unlock(&ctx->fdlock);
        return -EBADF;
    }

    is_cloexec = fd_is_cloexec(fd, ctx);

    spin_unlock(&ctx->fdlock);

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
    auto_file f;
    if (int st = f.from_fd(fd); st < 0)
        return st;

    /* TODO: Some flags, like O_ASYNC are not that simple to handle... */
    arg &= (O_APPEND | O_ASYNC | O_DIRECT | O_NOATIME | O_NONBLOCK);

    if (arg & O_NOATIME)
    {
        if (!may_noatime(f.get_file()))
            return -EPERM;
    }

    f.get_file()->f_flags = arg | (f.get_file()->f_flags & ~SETFL_MASK);

    return 0;
}

int default_fcntl(struct file *f, int cmd, unsigned long arg)
{
    return -EINVAL;
}

int sys_fcntl(int fd, int cmd, unsigned long arg)
{
    struct ioctx *ctx = &get_current_process()->ctx;

    int ret = 0;
    switch (cmd)
    {
        case F_DUPFD:
        case F_DUPFD_CLOEXEC: {
            auto_file f;

            if (int st = f.from_fd(fd); st < 0)
                return st;

            return do_dupfd(f.get_file(), (int) arg, cmd == F_DUPFD_CLOEXEC);
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

        default: {
            // Call the file's fcntl method if it exists
            auto_file f;

            if (int st = f.from_fd(fd); st < 0)
                return st;

            const auto ino = f.get_file()->f_ino;
            const auto fcntl_ = ino->i_fops->fcntl ?: default_fcntl;
            ret = fcntl_(f.get_file(), cmd, arg);
            break;
        }
    }

    return ret;
}

#define FSTATAT_VALID_FLAGS (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)

int sys_fstatat(int dirfd, const char *upathname, struct stat *ubuf, int flags)
{
    if (flags & ~FSTATAT_VALID_FLAGS)
        return -EINVAL;

    user_string s;
    if (auto ex = s.from_user(upathname); ex.has_error())
        return ex.error();

    struct stat buf = {};
    auto_file f;
    if (const int st = f.from_dirfd(dirfd); st < 0)
        return st;

    int st = 0;

    if (flags & AT_EMPTY_PATH && strlen(s.data()) == 0)
    {
        st = stat_vfs(&buf, f.get_file());
    }
    else
    {
        unsigned int open_flags = 0;
        if (flags & AT_SYMLINK_NOFOLLOW)
            open_flags |= OPEN_FLAG_NOFOLLOW;

        auto_file f2 = open_vfs_with_flags(f.get_file(), s.data(), open_flags);

        if (!f2)
        {
            return -errno;
        }

        st = stat_vfs(&buf, f2.get_file());
    }

    if (st == 0)
    {
        if (copy_to_user(ubuf, &buf, sizeof(buf)) < 0)
        {
            st = -EFAULT;
        }
    }

    return st;
}

int sys_stat(const char *upathname, struct stat *ubuf)
{
    return sys_fstatat(AT_FDCWD, upathname, ubuf, 0);
}

int sys_lstat(const char *upathname, struct stat *ubuf)
{
    return sys_fstatat(AT_FDCWD, upathname, ubuf, AT_SYMLINK_NOFOLLOW);
}

int sys_fstat(int fd, struct stat *ubuf)
{
    struct stat buf = {};
    auto_file f;
    if (int st = f.from_fd(fd); st < 0)
        return st;
    if (int st = stat_vfs(&buf, f.get_file()); st < 0)
        return st;
    return copy_to_user(ubuf, &buf, sizeof(buf));
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

    if (!S_ISDIR(dir->f_ino->i_mode))
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
        free((void *) path);
    return st;
}

int sys_fchdir(int fildes)
{
    struct file *f = get_file_description(fildes);
    if (!f)
        return -errno;

    struct file *node = f;
    if (!S_ISDIR(node->f_ino->i_mode))
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

    free((char *) path);
    if (dirfd_desc)
        fd_put(dirfd_desc);

    return fd;
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

    free((void *) path);
    fd_put(f);
    return st;
}

void file_do_cloexec(struct ioctx *ctx)
{
    scoped_lock g{ctx->fdlock};
    struct file **fd = ctx->file_desc;

    for (unsigned int i = 0; i < ctx->file_desc_entries; i++)
    {
        if (!fd[i])
            continue;
        if (fd_is_cloexec(i, ctx))
        {
            /* Close the file */
            // FIXME: Doing this under a spinlock is not correct and does crash if the struct file
            // cleanup needs to grab a lock. for instance, during any possible writeback
            auto file = __file_close_unlocked(i, get_current_process()).unwrap();
            fd_put(file);
        }
    }
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
        return -errno;
    }

    node->f_seek = 0;
    node->f_flags = flags;
    handle_open_flags(node, flags);
    bool cloexec = flags & O_CLOEXEC;
    fd_set_cloexec(fd_num, cloexec, ioctx);

    spin_unlock(&ioctx->fdlock);
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

    if (!S_ISDIR(dir->f_ino->i_mode))
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

    free((char *) path);
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

    if (!S_ISDIR(dir->f_ino->i_mode))
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

    free((char *) path);
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
    if ((ssize_t) bufsiz < 0)
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

int chmod_vfs(struct inode *ino, mode_t mode)
{
    ino->i_mode = (ino->i_mode & S_IFMT) | (mode & 07777);
    inode_update_ctime(ino);
    return 0;
}

#define VALID_FCHMODAT_FLAGS (AT_SYMLINK_NOFOLLOW)

int sys_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{
    if (flags & ~VALID_FCHMODAT_FLAGS)
        return -EINVAL;

    user_string path;
    if (auto ex = path.from_user(pathname); ex.has_error())
        return ex.error();

    auto_file dir;
    if (int st = dir.from_dirfd(dirfd); st < 0)
        return st;

    int open_flags = (flags & AT_SYMLINK_NOFOLLOW ? OPEN_FLAG_NOFOLLOW : 0);
    auto_file f = open_vfs_with_flags(dir.get_file(), path.data(), open_flags);

    if (!f)
        return -errno;

    int st = chmod_vfs(f.get_file()->f_ino, mode);

    return st;
}

int sys_fchmod(int fd, mode_t mode)
{
    auto_file f;
    if (int st = f.from_fd(fd); st < 0)
        return st;

    return chmod_vfs(f.get_file()->f_ino, mode);
}

int sys_chmod(const char *pathname, mode_t mode)
{
    return sys_fchmodat(AT_FDCWD, pathname, mode, 0);
}

void utimensat_vfs(inode *ino, timespec ktimes[2])
{
    bool set_time = false;
    for (unsigned int i = 0; i < 2; i++)
    {
        if (ktimes[i].tv_nsec == UTIME_NOW)
        {
            hrtime_to_timespec(clocksource_get_time(), &ktimes[i]);
        }
        else if (ktimes[i].tv_nsec == UTIME_OMIT)
            continue;

        set_time = true;
        // TODO: Nanosecond resolution in inode timestamps
        switch (i)
        {
            case 0:
                // atime
                ino->i_atime = ktimes[i].tv_sec;
                break;
            case 1:
                ino->i_mtime = ktimes[i].tv_sec;
                break;
        }
    }

    if (set_time)
    {
        // Note: dirties the inode
        inode_update_ctime(ino);
    }
}

#define VALID_UTIMENSAT_FLAGS (AT_SYMLINK_NOFOLLOW)

int sys_utimensat(int dirfd, const char *pathname, const struct timespec *times, int flags)
{
    if (flags & ~VALID_FCHMODAT_FLAGS)
        return -EINVAL;

    user_string path;

    if (pathname)
    {
        if (auto ex = path.from_user(pathname); ex.has_error())
            return ex.error();
    }

    struct timespec ktimes[2];

    if (copy_from_user(ktimes, times, sizeof(ktimes)) < 0)
        return -EFAULT;

    auto_file dir;

    auto_file f;
    if (pathname)
    {
        if (int st = dir.from_dirfd(dirfd); st < 0)
            return st;

        int open_flags = (flags & AT_SYMLINK_NOFOLLOW ? OPEN_FLAG_NOFOLLOW : 0);
        f = open_vfs_with_flags(dir.get_file(), path.data(), open_flags);

        if (!f)
            return -errno;
    }
    else
    {
        // Ok, let's use dirfd as the file to use
        // dirfd cannot be AT_FDCWD
        if (dirfd == AT_FDCWD)
            return -EFAULT;
        if (int st = f.from_fd(dirfd); st < 0)
            return st;
    }

    utimensat_vfs(f.get_file()->f_ino, ktimes);

    return 0;
}

static bool may_change_owner(inode *ino)
{
    return is_root_user();
}

static bool may_change_group(inode *ino, gid_t group)
{
    creds_guard g;
    auto creds = g.get();

    if (creds->euid == 0)
        return true; // Root can always change it, arbitrarily

    return ino->i_uid == creds->euid && (creds->egid == group || cred_is_in_group(creds, group));
}

int chown_vfs(inode *ino, uid_t owner, gid_t group)
{
    bool changed_inode = false;
    if (owner != (uid_t) -1 && ino->i_uid != owner)
    {
        if (!may_change_owner(ino))
            return -EPERM;

        ino->i_uid = owner;
        changed_inode = true;
    }

    if (group != (gid_t) -1 && ino->i_gid != group)
    {
        if (!may_change_group(ino, group))
            return -EPERM;

        ino->i_gid = group;
        changed_inode = true;
    }

    if (changed_inode)
    {
        // Clear SUID and SGID
        ino->i_mode &= ~S_ISUID;

        // If group-exec was not set, sgid would mean mandatory locking,
        // so we would not clear sgid.
        if (ino->i_mode & S_IXGRP)
        {
            ino->i_mode &= ~S_ISGID;
        }

        inode_update_ctime(ino);
    }

    return 0;
}

#define VALID_FCHOWNAT_FLAGS (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)

int sys_fchownat_core(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
{
    if (flags & ~VALID_FCHOWNAT_FLAGS)
        return -EINVAL;

    auto_file f;

    if (strlen(pathname) == 0)
    {
        if (!(flags & AT_EMPTY_PATH))
            return -ENOENT;
        // Empty path, interpret as dirfd = ino
        if (int st = f.from_dirfd(dirfd); st < 0)
            return st;
    }
    else
    {
        auto_file dir;
        if (int st = dir.from_dirfd(dirfd); st < 0)
            return st;

        int open_flags = (flags & AT_SYMLINK_NOFOLLOW ? OPEN_FLAG_NOFOLLOW : 0);
        f = open_vfs_with_flags(dir.get_file(), pathname, open_flags);

        if (!f)
            return -errno;
    }

    return chown_vfs(f.get_file()->f_ino, owner, group);
}

int sys_fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
{
    user_string s;
    if (auto ex = s.from_user(pathname); ex.has_error())
        return ex.error();
    return sys_fchownat_core(dirfd, s.data(), owner, group, flags);
}

int sys_chown(const char *pathname, uid_t owner, gid_t group)
{
    return sys_fchownat(AT_FDCWD, pathname, owner, group, 0);
}

int sys_fchown(int fd, uid_t owner, gid_t group)
{
    return sys_fchownat_core(fd, "", owner, group, AT_EMPTY_PATH);
}

int sys_lchown(const char *pathname, uid_t owner, gid_t group)
{
    return sys_fchownat(AT_FDCWD, pathname, owner, group, AT_SYMLINK_NOFOLLOW);
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
    buf->f_fsid.__val[0] = (int) sb->s_devnr;
    buf->f_fsid.__val[1] = (int) (sb->s_devnr >> 32);

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

static struct slab_cache *file_cache = nullptr;

/**
 * @brief Allocate a struct file
 *
 * @return Pointer to struct file, or nullptr
 */
file *file_alloc()
{
    return (file *) kmem_cache_alloc(file_cache, 0);
}
/**
 * @brief Free a struct file
 *
 * @arg file Pointer to struct file
 */
void file_free(struct file *file)
{
    kmem_cache_free(file_cache, (void *) file);
}

/**
 * @brief Initialize the file cache
 *
 */
void file_cache_init()
{
    file_cache = kmem_cache_create("file", sizeof(file), 0, 0, nullptr);
    if (!file_cache)
        panic("Could not allocate slab cache for struct file");
}
