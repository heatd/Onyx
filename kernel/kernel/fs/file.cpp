/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <onyx/compiler.h>
#include <onyx/dentry.h>
#include <onyx/file.h>
#include <onyx/fs_mount.h>
#include <onyx/limits.h>
#include <onyx/mm/slab.h>
#include <onyx/namei.h>
#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/rcupdate.h>
#include <onyx/user.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include <uapi/fcntl.h>
#include <uapi/flock.h>
#include <uapi/posix-types.h>
#include <uapi/stat.h>

/**
 * @brief Allocate a struct fd_table
 *
 * @return Pointer to struct fd_table, or nullptr
 */
static fd_table *fdtable_alloc();

/**
 * @brief Free a struct fd_table
 *
 * @arg file Pointer to struct fd_table
 */
void fdtable_free(struct fd_table *table);

static struct path get_current_directory()
{
    struct fsctx *ctx = get_current_process()->fs;
    struct path p;
    spin_lock(&ctx->cwd_lock);
    p = ctx->cwd;
    path_get(&p);
    spin_unlock(&ctx->cwd_lock);
    return p;
}

void fd_get(struct file *fd)
{
    __atomic_add_fetch(&fd->f_refcount, 1, __ATOMIC_ACQUIRE);
}

__always_inline bool fd_get_rcu(struct file *fd)
{
    // Do cmpxchg and bail if the refcount is 0.
    // If the refcount is 0, this file is on the waiting queue for destruction (or getting
    // destroyed)
    unsigned long expected;
    unsigned long to_store;
    do
    {
        expected = __atomic_load_n(&fd->f_refcount, __ATOMIC_RELAXED);
        if (expected == 0) [[unlikely]]
            return false;
        to_store = expected + 1;
    } while (!__atomic_compare_exchange_n(&fd->f_refcount, &expected, to_store, false,
                                          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));

    return true;
}

void fd_put(struct file *fd)
{
    if (__atomic_sub_fetch(&fd->f_refcount, 1, __ATOMIC_RELEASE) == 0)
    {
        if (fd->f_flock)
            flock_release(fd);

        if (file_needs_unlock(fd))
            flock_remove_ofd(fd);

        if (fd->f_ino->i_fops->release)
            fd->f_ino->i_fops->release(fd);

        close_vfs(fd->f_ino);
        // printk("file %s dentry refs %lu\n", fd->f_dentry->d_name, fd->f_dentry->d_ref);
        path_put(&fd->f_path);
        file_free(fd);
    }
}

static inline bool fd_is_open(int fd, struct fd_table *ctx)
{
    unsigned long long_idx = fd / FDS_PER_LONG;
    unsigned long bit_idx = fd % FDS_PER_LONG;
    return ctx->open_fds[long_idx] & (1UL << bit_idx);
}

static bool validate_fd_number(int fd, struct fd_table *ctx)
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

static inline void fd_close_bit(int fd, struct fd_table *ctx)
{
    unsigned long long_idx = fd / FDS_PER_LONG;
    unsigned long bit_idx = fd % FDS_PER_LONG;
    ctx->open_fds[long_idx] &= ~(1UL << bit_idx);
}

void fd_set_cloexec(int fd, bool toggle, struct fd_table *ctx)
{
    unsigned long long_idx = fd / FDS_PER_LONG;
    unsigned long bit_idx = fd % FDS_PER_LONG;

    if (toggle)
        ctx->cloexec_fds[long_idx] |= (1UL << bit_idx);
    else
        ctx->cloexec_fds[long_idx] &= ~(1UL << bit_idx);
}

void fd_set_open(int fd, bool toggle, struct fd_table *ctx)
{
    unsigned long long_idx = fd / FDS_PER_LONG;
    unsigned long bit_idx = fd % FDS_PER_LONG;

    if (toggle)
        ctx->open_fds[long_idx] |= (1UL << bit_idx);
    else
        ctx->open_fds[long_idx] &= ~(1UL << bit_idx);
}

bool fd_is_cloexec(int fd, struct fd_table *ctx)
{
    unsigned long long_idx = fd / FDS_PER_LONG;
    unsigned long bit_idx = fd % FDS_PER_LONG;

    return ctx->cloexec_fds[long_idx] & (1UL << bit_idx);
}

struct file *__get_file_description_unlocked(int fd, struct process *p)
{
    struct ioctx *ctx = p->ctx;

    while (true)
    {
        struct fd_table *table = rcu_dereference(ctx->table);
        if (!validate_fd_number(fd, table))
            break;

        struct file *f = rcu_dereference(table->file_desc[fd]);
        if (!f)
            break;

        if (!fd_get_rcu(f))
            continue;

        // Note: maybe we should keep CVE-2021-4083 in mind?

        return f;
    }

    errno = EBADF;
    return nullptr;
}

#define FDGET_SHARED (1 << 0)
#define FDGET_SEEK   (1 << 1)

static inline bool needs_seek_lock(struct file *f)
{
    auto mode = f->f_ino->i_mode;
    return S_ISDIR(mode) || S_ISREG(mode);
}

/**
 * @brief RAII wrapper that neatly handles skipping fd_put and seek locks on files that *cannot* be
 * shared
 *
 */
class auto_fd
{
    struct file *f;
    int flags;

public:
    auto_fd(struct file *file, int flags) : f{file}, flags{flags}
    {
        if (f) [[likely]]
        {
            if (flags & FDGET_SEEK)
            {
                /* We can skip locking seek if 1) the file type doesn't need it; and 2) we are not
                 * sharing this file with anyone else.
                 */
                if (needs_seek_lock(file) && file->f_refcount > 1)
                    mutex_lock(&f->f_seeklock);
                else
                    this->flags &= ~FDGET_SEEK;
            }
        }
    }

    ~auto_fd()
    {
        if (f) [[likely]]
        {
            if (flags & FDGET_SEEK)
                mutex_unlock(&f->f_seeklock);
            if (flags & FDGET_SHARED)
                fd_put(f);
        }
    }

    operator file *() const
    {
        return f;
    }

    struct file *get_file() const
    {
        return f;
    }

    file *release()
    {
        file *ret = f;
        f = nullptr;
        return ret;
    }

    bool has_seek() const
    {
        return flags & FDGET_SEEK;
    }
};

struct file *__get_file_description(int fd, struct process *p)
{
    rcu_read_lock();
    struct file *f = __get_file_description_unlocked(fd, p);
    rcu_read_unlock();
    return f;
}

__always_inline auto_fd __fdget(int fd, u8 extra_flags)
{
    struct process *p = get_current_process();

    /* This is safe. refs cannot increment from 1 as long as we're here (we are the only
     * thread).
     */
    struct ioctx *ctx = p->ctx;
    if (refcount_read(&ctx->refs) > 1 || p->nr_threads > 1 || extra_flags & FDGET_SHARED)
        return auto_fd{__get_file_description(fd, p), extra_flags | FDGET_SHARED};

    /* Cheap single threaded array access */
    struct fd_table *table = rcu_dereference(ctx->table);
    if (!validate_fd_number(fd, table))
        return errno = EBADF, auto_fd{nullptr, false};

    struct file *f = rcu_dereference(table->file_desc[fd]);
    if (!f)
        return errno = EBADF, auto_fd{nullptr, false};

    return auto_fd{f, extra_flags};
}

auto_fd fdget(int fd)
{
    return __fdget(fd, 0);
}

/**
 * @brief fdget and deal with seek locking
 *
 * @param fd File descriptor to grab
 * @return auto_fd
 */
auto_fd fdget_seek(int fd)
{
    return __fdget(fd, FDGET_SEEK);
}

expected<file *, int> __file_close_unlocked(int fd, struct process *p)
{
    // printk("pid %d close %d\n", get_current_process()->pid, fd);
    struct ioctx *ctx = p->ctx;
    struct fd_table *table = ctx->table;

    if (!validate_fd_number(fd, table))
        return unexpected<int>{-EBADF};

    struct file *f = table->file_desc[fd];

    /* Set the entry to nullptr */
    /* TODO: Shrink the fd table? */
    fd_close_bit(fd, table);
    rcu_assign_pointer(table->file_desc[fd], nullptr);

    return f;
}

void filp_close(struct file *filp)
{
    if (file_needs_unlock(filp))
        flock_remove_posix(filp);
    fd_put(filp);
}

int __file_close(int fd, struct process *p)
{
    struct ioctx *ctx = p->ctx;

    spin_lock(&ctx->fdlock);

    auto ex = __file_close_unlocked(fd, p);

    spin_unlock(&ctx->fdlock);

    if (ex.has_error())
        return ex.error();

    filp_close(ex.value());
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

static int dup_fdtable(struct ioctx *ctx, struct fd_table *table)
{
    struct fd_table *oldt = ctx->table;
    unsigned int nr_fds = oldt->file_desc_entries;

    /* Release the ioctx lock, required for the next few allocations */
    spin_unlock(&ctx->fdlock);

    table->file_desc = (file **) kmalloc(nr_fds * sizeof(void *), GFP_KERNEL);
    table->file_desc_entries = nr_fds;
    if (!table->file_desc)
        return -ENOMEM;

    table->cloexec_fds = (unsigned long *) kmalloc(nr_fds / 8, GFP_KERNEL);
    if (!table->cloexec_fds)
    {
        kfree(table->file_desc);
        return -ENOMEM;
    }

    table->open_fds = (unsigned long *) kmalloc(nr_fds / 8, GFP_KERNEL);
    if (!table->open_fds)
    {
        kfree(table->file_desc);
        kfree(table->cloexec_fds);
        return -ENOMEM;
    }

    spin_lock(&ctx->fdlock);
    return 0;
}

int copy_file_descriptors(struct process *process, struct ioctx *ctx)
{
    int err;
    struct fd_table *oldt;
    struct fd_table *table = fdtable_alloc();
    if (!table)
        return -ENOMEM;

    spin_lock(&ctx->fdlock);

    for (;;)
    {
        err = dup_fdtable(ctx, table);
        /* dup_fdtable drops the lock and doesn't re-lock on error */
        if (err)
            return err;
        if (table->file_desc_entries >= ctx->table->file_desc_entries)
            break;

        /* Need to re-alloc everything, so free the old data */
        kfree(table->cloexec_fds);
        kfree(table->file_desc);
        kfree(table->open_fds);
        table->file_desc_entries = 0;
    }

    oldt = ctx->table;
    memcpy(table->cloexec_fds, oldt->cloexec_fds, table->file_desc_entries / 8);
    memcpy(table->open_fds, oldt->open_fds, table->file_desc_entries / 8);

    for (unsigned int i = 0; i < table->file_desc_entries; i++)
    {
        rcu_assign_pointer(table->file_desc[i], oldt->file_desc[i]);
        if (fd_is_open(i, table))
            fd_get(table->file_desc[i]);
    }

    spin_unlock(&ctx->fdlock);
    rcu_assign_pointer(process->ctx->table, table);
    return 0;
}

int allocate_file_descriptor_table(struct process *process)
{
    fd_table *table = fdtable_alloc();
    if (!table)
        return -ENOMEM;

    table->file_desc = (file **) kcalloc(FILE_DESCRIPTOR_GROW_NR, sizeof(void *), GFP_KERNEL);
    if (!table->file_desc)
        return -ENOMEM;

    table->file_desc_entries = FILE_DESCRIPTOR_GROW_NR;

    table->cloexec_fds = (unsigned long *) kcalloc(FILE_DESCRIPTOR_GROW_NR / 8, 1, GFP_KERNEL);
    if (!table->cloexec_fds)
    {
        free(table->file_desc);
        return -ENOMEM;
    }

    table->open_fds = (unsigned long *) kcalloc(FILE_DESCRIPTOR_GROW_NR / 8, 1, GFP_KERNEL);
    if (!table->open_fds)
    {
        free(table->file_desc);
        free(table->cloexec_fds);
        return -1;
    }

    rcu_assign_pointer(process->ctx->table, table);

    return 0;
}

static void defer_free_fd_table_rcu(fd_table *table_)
{
    call_rcu(&table_->rcuhead, [](struct rcu_head *head) {
        fd_table *table = container_of(head, fd_table, rcuhead);
        free(table->file_desc);
        free(table->cloexec_fds);
        free(table->open_fds);
        fdtable_free(table);
    });
}

#define FD_ENTRIES_TO_FDSET_SIZE(x) ((x) / 8)

/* Enlarges the file descriptor table by FILE_DESCRIPTOR_GROW_NR(64) entries */
static int enlarge_fdtable(struct process *process, unsigned int new_size)
{
    int err = -ENOMEM;
    struct fd_table *oldt = process->ctx->table;
    unsigned int old_nr_fds = oldt->file_desc_entries;
    struct fd_table *table = nullptr;
    struct file **ftable = nullptr;
    unsigned long *cloexec_fds = nullptr;
    unsigned long *open_fds = nullptr;

    new_size = ALIGN_TO(new_size, FILE_DESCRIPTOR_GROW_NR);
    if (new_size > INT_MAX || new_size >= process->get_rlimit(RLIMIT_NOFILE).rlim_cur)
        return -EMFILE;

    /* Can't allocate with the fdlock held... */
    spin_unlock(&process->ctx->fdlock);

    table = fdtable_alloc();
    if (!table)
        goto error;

    ftable = (struct file **) kcalloc(new_size, sizeof(void *), GFP_KERNEL);
    cloexec_fds = (unsigned long *) kcalloc(FD_ENTRIES_TO_FDSET_SIZE(new_size), 1, GFP_KERNEL);
    /* We use kcalloc here to implicitly zero free fds */
    open_fds = (unsigned long *) kcalloc(FD_ENTRIES_TO_FDSET_SIZE(new_size), 1, GFP_KERNEL);
    if (!ftable || !cloexec_fds || !open_fds)
        goto error;

    spin_lock(&process->ctx->fdlock);
    if (process->ctx->table != oldt)
    {
        /* Someone changed the fd table while we were gone, retry */
        err = -EAGAIN;
        goto error_nolock;
    }

    DCHECK(process->ctx->table->file_desc_entries == old_nr_fds);
    /* Note that we use old_nr_fds for these copies specifically as to not go
     * out of bounds.
     */
    memcpy(ftable, oldt->file_desc, (old_nr_fds) * sizeof(void *));
    memcpy(cloexec_fds, oldt->cloexec_fds, FD_ENTRIES_TO_FDSET_SIZE(old_nr_fds));
    memcpy(open_fds, oldt->open_fds, FD_ENTRIES_TO_FDSET_SIZE(old_nr_fds));

    table->file_desc_entries = new_size;
    rcu_assign_pointer(table->file_desc, ftable);
    rcu_assign_pointer(table->cloexec_fds, cloexec_fds);
    rcu_assign_pointer(table->open_fds, open_fds);

    rcu_assign_pointer(process->ctx->table, table);
    defer_free_fd_table_rcu(oldt);

    return 0;

error:
    spin_lock(&process->ctx->fdlock);
error_nolock:
    if (table)
        fdtable_free(table);
    free(ftable);
    free(cloexec_fds);
    free(open_fds);

    return err;
}

static void close_all_fds(struct ioctx *ctx)
{
    fd_table *table = ctx->table;
    file **ftable = table->file_desc;

    for (unsigned int i = 0; i < table->file_desc_entries; i++)
    {
        if (!fd_is_open(i, table))
            continue;

        filp_close(ftable[i]);
    }

    rcu_assign_pointer(ctx->table, nullptr);
    defer_free_fd_table_rcu(table);
}

void exit_files(struct process *process)
{
    struct ioctx *ctx = process->ctx;
    if (refcount_dec_and_test(&ctx->refs))
    {
        close_all_fds(ctx);
        kfree(ctx);
    }
}

int alloc_fd(int fdbase)
{
    auto current = get_current_process();

    if (fdbase < 0 || fdbase == INT_MAX ||
        (unsigned int) fdbase >= current->get_rlimit(RLIMIT_NOFILE).rlim_cur)
        return -EBADF;

    struct ioctx *ioctx = current->ctx;
    scoped_lock g{ioctx->fdlock};

    unsigned long starting_long = fdbase / FDS_PER_LONG;

    while (true)
    {
        struct fd_table *table = ioctx->table;
        unsigned long nr_longs = table->file_desc_entries / FDS_PER_LONG;

        for (unsigned long i = starting_long; i < nr_longs; i++)
        {
            if (table->open_fds[i] == ULONG_MAX)
                continue;

            /* We speed it up by doing an ffz. */
            unsigned int first_free = __builtin_ctzl(~table->open_fds[i]);

            for (unsigned int j = first_free; j < FDS_PER_LONG; j++)
            {
                int fd = FDS_PER_LONG * i + j;

                if (table->open_fds[i] & (1UL << j))
                    continue;

                if (fd < fdbase)
                    continue;
                else
                {
                    /* Check against the file limit */
                    if (current->get_rlimit(RLIMIT_NOFILE).rlim_cur < (unsigned long) fd)
                        return -EMFILE;
                    /* Found a free fd that we can use, let's mark it used and return it */
                    table->open_fds[i] |= (1UL << j);
                    /* And don't forget to reset the cloexec flag! */
                    fd_set_cloexec(fd, false, table);
                    g.keep_locked();
                    return fd;
                }
            }
        }

        /* TODO: Make it so we can enlarge it directly to the size we want */
        int new_entries = table->file_desc_entries + FILE_DESCRIPTOR_GROW_NR;
        if (int st = enlarge_fdtable(current, new_entries); st < 0)
        {
            if (st == -EAGAIN)
                continue;
            return st;
        }
    }
}

int file_alloc(struct file *f, struct ioctx *ioctx)
{
    assert(f != nullptr);
    int filedesc = alloc_fd(0);
    if (filedesc < 0)
        return errno = -filedesc, filedesc;

    ioctx->table->file_desc[filedesc] = f;
    fd_get(f);

    return filedesc;
}

ssize_t sys_read(int fd, const void *buf, size_t count)
{
    auto_fd f = fdget_seek(fd);
    if (!f)
        return -errno;

    auto fil = f.get_file();

    if (!fd_may_access(fil, FILE_ACCESS_READ))
        return -EBADF;

    ssize_t size = read_vfs(fil->f_seek, count, (char *) buf, fil);

    if (size > 0)
        fil->f_seek += size;

    return size;
}

ssize_t sys_write(int fd, const void *buf, size_t count)
{
    auto_fd f = fdget_seek(fd);
    if (!f)
        return -errno;

    auto fil = f.get_file();

    if (!fd_may_access(fil, FILE_ACCESS_WRITE))
        return -EBADF;

    if (fil->f_flags & O_APPEND)
        fil->f_seek = fil->f_ino->i_size;

    auto written = write_vfs(fil->f_seek, count, (void *) buf, fil);

    if (written > 0)
        fil->f_seek += written;

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
    fd->f_flags = flags;
    if (flags & O_APPEND)
        fd->f_seek = fd->f_ino->i_size;
}

bool may_noatime(file *f)
{
    creds_guard g;
    return g.get()->euid == 0 || f->f_ino->i_uid == g.get()->euid;
}

static expected<struct file *, int> try_to_open(int dirfd, const char *filename, int flags,
                                                mode_t mode)
{
    auto ex = vfs_open(dirfd, filename, flags, mode);
    if (ex.has_error())
        return unexpected<int>{ex.error()};

    struct file *ret = ex.value();

    DCHECK(ret != nullptr);

    if (ret)
    {
        /* Let's check for permissions */
        if (!file_can_access(ret, open_to_file_access_flags(flags)))
        {
            fd_put(ret);
            return unexpected<int>{-EACCES};
        }

        // O_NOATIME can only be used when the euid of the process = owner of file, or
        // when we're privileged (root).
        if (flags & O_NOATIME)
        {
            if (!may_noatime(ret))
            {
                fd_put(ret);
                return unexpected<int>{-EPERM};
            }
        }

        if (S_ISDIR(ret->f_ino->i_mode))
        {
            if (flags & O_RDWR || flags & O_WRONLY || (flags & O_CREAT && !(flags & O_DIRECTORY)))
            {
                fd_put(ret);
                return unexpected<int>{-EISDIR};
            }
        }

        if (flags & O_TRUNC)
        {
            int st = ftruncate_vfs(0, ret);
            if (st < 0)
            {
                fd_put(ret);
                return unexpected<int>{st};
            }
        }
    }

    if (ret)
    {
        ret->f_seek = 0;
        ret->f_flags = flags;
    }

    return ret;
}

/* TODO: Add O_PATH */
#define VALID_OPEN_FLAGS                                                                       \
    (O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_DIRECTORY | O_EXCL | O_NOFOLLOW | O_NONBLOCK | \
     O_APPEND | O_CLOEXEC | O_LARGEFILE | O_TRUNC | O_NOCTTY | O_PATH | O_NOATIME | O_DIRECT | \
     O_SYNC)

int do_sys_open(const char *filename, int flags, mode_t mode, int dirfd)
{
    if (flags & ~VALID_OPEN_FLAGS)
    {
#if 0
        printk("Open(%s): Bad flags!\n", filename);
        printk("Flag mask %o\n", flags & ~VALID_OPEN_FLAGS);
#endif
        return -EINVAL;
    }
    /* This function does all the open() work, open(2) and openat(2) use this */
    int fd_num = -1;

    /* Open/creat the file */
    auto ex = try_to_open(dirfd, filename, flags, mode);
    if (ex.has_error())
    {
        return ex.error();
    }

    struct file *file = ex.value();

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
    /* open(2) does relative opens using the current working directory */
    int fd = do_sys_open(filename, flags, mode, AT_FDCWD);
    free((char *) filename);
    return fd;
}

int sys_close(int fd)
{
    return file_close(fd);
}

int sys_dup(int fd)
{
    int st = 0;
    struct ioctx *ioctx = get_current_process()->ctx;

    struct file *f = get_file_description(fd);
    if (!f)
        return -errno;

    int new_fd = alloc_fd(0);

    if (new_fd < 0)
    {
        st = new_fd;
        goto out_error;
    }

    rcu_assign_pointer(ioctx->table->file_desc[new_fd], f);

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
    struct ioctx *ioctx = current->ctx;
    struct fd_table *table;

    if (newfd < 0 || oldfd < 0)
        return -EBADF;

    struct file *newf_old = nullptr;

    /* We pass FDGET_SHARED so we always get an extra reference (for the dup). A normal fdget here
     * is wrong, as the behavior changes from single-threaded to multi-threaded. */
    auto_fd old = __fdget(oldfd, FDGET_SHARED);
    if (!old)
        return -EBADF;

    scoped_lock g{ioctx->fdlock};

retry:
    table = rcu_dereference(ioctx->table);
    if ((unsigned int) newfd >= ioctx->table->file_desc_entries)
    {
        int st = enlarge_fdtable(current, (unsigned int) newfd + 1);
        if (st < 0)
        {
            if (st == -EAGAIN)
            {
                /* EAGAIN = someone touched the fd table while allocating, retry */
                goto retry;
            }

            // open() expects EMFILE, dup2/3 expects EBADF
            if (st == -EMFILE)
                st = -EBADF;
            return st;
        }

        table = rcu_dereference(ioctx->table);
    }

    if (oldfd == newfd)
        return flags & DUP23_DUP3 ? -EINVAL : oldfd;

    if (table->file_desc[newfd])
    {
        auto ex = __file_close_unlocked(newfd, current);
        if (ex.has_error())
            return ex.error();

        newf_old = ex.value();
    }

    table->file_desc[newfd] = old.release();
    fd_set_cloexec(newfd, dupflags & O_CLOEXEC, table);
    fd_set_open(newfd, true, table);

    // printk("refs: %lu\n", f->f_refcount);

    /* Note: To avoid fd_get/fd_put, we use the ref we get from
     * get_file_description as the ref for newfd. Therefore, we don't
     * fd_get and fd_put().
     */

    g.unlock();

    if (newf_old)
        filp_close(newf_old);

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

#define FASTIOV_NR 8
struct iovec_guard
{
    struct iovec inline_vec[FASTIOV_NR];
    struct iovec *vec{inline_vec};
    size_t len{0};

    ~iovec_guard()
    {
        if (vec != inline_vec)
            kfree(vec);
    }

    /**
     * @brief Make an iterator from an iovec_guard
     *
     * @param count Count (has been sanitized by fetch_iovec)
     * @return iovec_iter
     */
    iovec_iter to_iter(int count) const
    {
        return iovec_iter{{vec, (size_t) count}, len, IOVEC_USER};
    }
};

/**
 * @brief Fetch iovecs from userspace and validate them
 *
 * @param uvec User pointer to iovecs
 * @param count *Unsanitized* number of vecs
 * @param guard Caller's iovec guard
 * @return Total length of iovecs, or negative error code
 */
static ssize_t fetch_iovec(const struct iovec *uvec, int count, iovec_guard &guard)
{
    if (count < 0 || count > IOV_MAX)
        return -EINVAL;

    if (count > FASTIOV_NR)
    {
        guard.vec = (struct iovec *) calloc(count, sizeof(struct iovec));
        if (!guard.vec)
            return -ENOMEM;
    }

    if (copy_from_user(guard.vec, uvec, count * sizeof(struct iovec)) < 0)
        return -EFAULT;
    guard.len = iovec_count_length(guard.vec, count);

    return guard.len;
}

ssize_t sys_readv(int fd, const struct iovec *vec, int veccnt)
{
    iovec_guard guard;
    ssize_t st = -EBADF;
    auto_fd f = fdget_seek(fd);
    if (!f)
        return st;

    if (!fd_may_access(f.get_file(), FILE_ACCESS_READ))
        return st;

    if (st = fetch_iovec(vec, veccnt, guard); st < 0)
        return st;

    iovec_iter iter = guard.to_iter(veccnt);

    st = read_iter_vfs(f.get_file(), f.get_file()->f_seek, &iter, 0);

    if (st > 0)
        f.get_file()->f_seek += st;
    return st;
}

ssize_t sys_writev(int fd, const struct iovec *vec, int veccnt)
{
    iovec_guard guard;
    ssize_t st = -EBADF;
    auto_fd f = fdget_seek(fd);
    if (!f)
        return st;

    struct file *filp = f.get_file();

    if (!fd_may_access(filp, FILE_ACCESS_WRITE))
        return st;

    if (st = fetch_iovec(vec, veccnt, guard); st < 0)
        return st;

    iovec_iter iter = guard.to_iter(veccnt);

    if (filp->f_flags & O_APPEND)
        filp->f_seek = filp->f_ino->i_size;

    st = write_iter_vfs(filp, filp->f_seek, &iter, 0);

    if (st > 0)
        filp->f_seek += st;
    return st;
}

ssize_t sys_preadv(int fd, const struct iovec *vec, int veccnt, off_t offset)
{
    iovec_guard guard;
    ssize_t st = -EBADF;
    auto_file f = get_file_description(fd);
    if (!f)
        return st;

    if (!fd_may_access(f.get_file(), FILE_ACCESS_READ))
        return st;

    if (st = fetch_iovec(vec, veccnt, guard); st < 0)
        return st;

    iovec_iter iter = guard.to_iter(veccnt);

    return read_iter_vfs(f.get_file(), offset, &iter, 0);
}

ssize_t sys_pwritev(int fd, const struct iovec *vec, int veccnt, off_t offset)
{
    iovec_guard guard;
    ssize_t st = -EBADF;
    auto_file f = get_file_description(fd);
    if (!f)
        return -EBADF;

    if (!fd_may_access(f.get_file(), FILE_ACCESS_WRITE))
        return -EBADF;

    if (st = fetch_iovec(vec, veccnt, guard); st < 0)
        return st;

    iovec_iter iter = guard.to_iter(veccnt);

    return write_iter_vfs(f.get_file(), offset, &iter, 0);
}

unsigned int putdir(struct dirent *buf, struct dirent *ubuf, unsigned int count);

int sys_getdents(int fd, struct dirent *dirp, unsigned int count)
{
    int ret = 0;
    if (!count)
        return -EINVAL;

    auto_fd f = fdget_seek(fd);
    if (!f)
        return -errno;

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
    off_t ret = 0;
    auto_fd f = fdget_seek(fd);
    if (!f)
        return -errno;

    struct file *filp = f.get_file();

    /* TODO: Add a way for inodes to tell they don't support seeking */
    if (S_ISFIFO(filp->f_ino->i_mode) || filp->f_ino->i_flags & INODE_FLAG_NO_SEEK)
        return -ESPIPE;

    if (whence == SEEK_CUR)
    {
        filp->f_seek += offset;
        ret = filp->f_seek;
    }
    else if (whence == SEEK_SET)
        ret = filp->f_seek = offset;
    else if (whence == SEEK_END)
        ret = filp->f_seek = filp->f_ino->i_size + offset;
    else
        ret = -EINVAL;

    return ret;
}

static int do_dupfd(struct file *f, int fdbase, bool cloexec)
{
    if (fdbase < 0)
        return -EINVAL;
    int new_fd = alloc_fd(fdbase);
    if (new_fd < 0)
    {
        if (new_fd == -EBADF)
            new_fd = -EINVAL;
        return new_fd;
    }

    struct ioctx *ioctx = get_current_process()->ctx;
    ioctx->table->file_desc[new_fd] = f;

    fd_get(f);

    fd_set_cloexec(new_fd, cloexec, ioctx->table);

    spin_unlock(&ioctx->fdlock);

    return new_fd;
}

int fcntl_f_getfd(int fd, struct ioctx *ctx)
{
    spin_lock(&ctx->fdlock);
    fd_table *table = ctx->table;

    if (!validate_fd_number(fd, table))
    {
        spin_unlock(&ctx->fdlock);
        return -EBADF;
    }

    int st = fd_is_cloexec(fd, table) ? FD_CLOEXEC : 0;

    spin_unlock(&ctx->fdlock);
    return st;
}

int fcntl_f_setfd(int fd, unsigned long arg, struct ioctx *ctx)
{
    spin_lock(&ctx->fdlock);
    fd_table *table = ctx->table;

    if (!validate_fd_number(fd, table))
    {
        spin_unlock(&ctx->fdlock);
        return -EBADF;
    }

    bool wants_cloexec = arg & FD_CLOEXEC;

    fd_set_cloexec(fd, wants_cloexec, table);

    spin_unlock(&ctx->fdlock);

    return 0;
}

int fcntl_f_getfl(int fd, struct ioctx *ctx)
{
    bool is_cloexec;

    spin_lock(&ctx->fdlock);

    fd_table *table = ctx->table;

    if (!validate_fd_number(fd, table))
    {
        spin_unlock(&ctx->fdlock);
        return -EBADF;
    }

    is_cloexec = fd_is_cloexec(fd, table);

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

static int fcntl_adv_lock(int fd, int cmd, struct flock *arg)
{
    /* Note: We need to use seek here for functionality internal usage */
    auto_fd file = fdget_seek(fd);
    if (!file)
        return -EBADF;
    return flock_do_posix(file.get_file(), cmd, arg, file.has_seek());
}

int sys_fcntl(int fd, int cmd, unsigned long arg)
{
    struct ioctx *ctx = get_current_process()->ctx;

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

        case F_GETLK:
        case F_SETLKW:
        case F_SETLK:
        case F_OFD_GETLK:
        case F_OFD_SETLK:
        case F_OFD_SETLKW:
            return fcntl_adv_lock(fd, cmd, (struct flock *) arg);

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

int sys_fstat(int fd, struct stat *);

int sys_fstatat(int dirfd, const char *upathname, struct stat *ubuf, int flags)
{
    if (flags & ~FSTATAT_VALID_FLAGS)
        return -EINVAL;

    user_string s;
    if (auto ex = s.from_user(upathname); ex.has_error())
        return ex.error();

    struct path path;
    struct stat buf = {};
    int st = 0;

    if (flags & AT_EMPTY_PATH && strlen(s.data()) == 0)
        return sys_fstat(dirfd, ubuf);

    unsigned int open_flags = 0;
    if (flags & AT_SYMLINK_NOFOLLOW)
        open_flags |= LOOKUP_NOFOLLOW;
    st = path_openat(dirfd, s.data(), open_flags, &path);
    if (st)
        return st;

    st = stat_vfs(&buf, &path);
    if (st == 0)
    {
        if (copy_to_user(ubuf, &buf, sizeof(buf)) < 0)
            st = -EFAULT;
    }

    path_put(&path);
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
    if (int st = stat_vfs(&buf, &f.get_file()->f_path); st < 0)
        return st;
    return copy_to_user(ubuf, &buf, sizeof(buf));
}

int sys_chdir(const char *upath)
{
    const char *path = strcpy_from_user(upath);
    if (!path)
        return -errno;

    int st = 0;
    struct process *current;
    struct fsctx *ctx;
    struct path newdir, old;
    st = path_openat(AT_FDCWD, path, LOOKUP_MUST_BE_DIR, &newdir);
    if (st < 0)
        goto out;

    /* The current working directory we chose must be searchable by the calling process */
    if (!inode_can_access(newdir.dentry->d_inode, FILE_ACCESS_EXECUTE))
    {
        path_put(&newdir);
        st = -EACCES;
        goto out;
    }

    current = get_current_process();
    ctx = current->fs;

    spin_lock(&ctx->cwd_lock);
    old = ctx->cwd;
    ctx->cwd = newdir;
    spin_unlock(&ctx->cwd_lock);

    /* We've swapped ptrs atomically and now we're dropping the cwd reference.
     * Note that any current users of the cwd are using it properly.
     */
    path_put(&old);
out:
    if (path)
        free((void *) path);
    return st;
}

int sys_fchdir(int fildes)
{
    int st = 0;
    struct path old;
    path_init(&old);

    struct file *f = get_file_description(fildes);
    if (!f)
        return -errno;

    if (!S_ISDIR(f->f_ino->i_mode))
    {
        st = -ENOTDIR;
        goto out;
    }

    /* The current working directory we chose must be searchable by the calling process */
    if (!inode_can_access(f->f_ino, FILE_ACCESS_EXECUTE))
    {
        st = -EACCES;
        goto out;
    }

    struct process *current;
    struct fsctx *ctx;

    current = get_current_process();
    ctx = current->fs;

    spin_lock(&ctx->cwd_lock);
    old = ctx->cwd;
    ctx->cwd = f->f_path;
    path_get(&ctx->cwd);
    spin_unlock(&ctx->cwd_lock);

out:
    /* We've swapped ptrs atomically and now we're dropping the cwd reference.
     * Note that any current users of the cwd are using it properly.
     */
    fd_put(f);
    path_put(&old);

    return st;
}

int sys_getcwd(char *path, size_t size)
{
    char pathbuf[PATH_MAX];
    size_t pathlen = 0;
    if (size == 0 && path != nullptr)
        return -EINVAL;

    struct path cwd = get_current_directory();
    char *name = d_path(&cwd, pathbuf, PATH_MAX);
    path_put(&cwd);
    if (IS_ERR(name))
        return PTR_ERR(name);

    pathlen = pathbuf + PATH_MAX - name;
    if (pathlen > size)
        return -ERANGE;

    if (copy_to_user(path, name, pathlen) < 0)
        return -errno;

    return pathlen - 1;
}

int get_dirfd(int dirfd, struct path *cwd)
{
    if (!get_current_process())
    {
        /* If we do *not* have a process, return root */
        WARN_ON(dirfd != AT_FDCWD);
        *cwd = get_filesystem_root();
        return 0;
    }

    if (dirfd != AT_FDCWD)
    {
        auto_fd fd = fdget(dirfd);
        if (!fd)
            return -EBADF;
        *cwd = fd.get_file()->f_path;
        path_get(cwd);
        return 0;
    }
    else
        *cwd = get_current_directory();

    return 0;
}

int sys_openat(int dirfd, const char *upath, int flags, mode_t mode)
{
    const char *path = strcpy_from_user(upath);
    if (!path)
        return -errno;

    int fd = do_sys_open(path, flags, mode, dirfd);
    free((char *) path);
    return fd;
}

int sys_fmount(int fd, const char *upath)
{
    return 0;
}

void file_do_cloexec(struct ioctx *ctx)
{
    fd_table *table = ctx->table;

    struct file **fd = table->file_desc;

    for (unsigned int i = 0; i < table->file_desc_entries; i++)
    {
        if (!fd[i])
            continue;
        if (fd_is_cloexec(i, table))
        {
            /* Close the file */
            // FIXME: Doing this under a spinlock is not correct and does crash if the struct file
            // cleanup needs to grab a lock. for instance, during any possible writeback
            auto file = __file_close_unlocked(i, get_current_process()).unwrap();
            filp_close(file);
        }
    }
}

int open_with_vnode(struct file *node, int flags)
{
    /* This function does all the open() work, open(2) and openat(2) use this */
    struct ioctx *ioctx = get_current_process()->ctx;

    int fd_num = -1;
    /* Allocate a file descriptor and a file description for the file */
    fd_num = file_alloc(node, ioctx);
    if (fd_num < 0)
    {
        return -errno;
    }

    handle_open_flags(node, flags);
    bool cloexec = flags & O_CLOEXEC;
    fd_set_cloexec(fd_num, cloexec, ioctx->table);

    spin_unlock(&ioctx->fdlock);
    return fd_num;
}

int sys_faccessat(int dirfd, const char *upath, int amode, int flags)
{
    // TODO: Implement flags, we're doing the check wrong(it should be with ruid
    // instead of euid by default)
    user_string path;
    auto_file f;

    if (auto res = path.from_user(upath); res.has_error())
        return -EFAULT;

    auto_file file = open_vfs(dirfd, path.data());

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

int sys_mkdirat(int dirfd, const char *upath, mode_t mode)
{
    char *path = strcpy_from_user(upath);
    if (!path)
        return -errno;

    int err = 0;

    auto ex = mkdir_vfs(path, mode & ~get_current_umask(), dirfd);
    if (ex.has_error())
        err = ex.error();
    else
        dput(ex.value());
    free((char *) path);
    return err;
}

int sys_mkdir(const char *upath, mode_t mode)
{
    return sys_mkdirat(AT_FDCWD, upath, mode);
}

int sys_mknodat(int dirfd, const char *upath, mode_t mode, dev_t dev)
{
    char *path = strcpy_from_user(upath);
    if (!path)
        return -errno;

    int err = 0;

    auto ex = mknod_vfs(path, mode & ~get_current_umask(), dev, dirfd);
    if (ex.has_error())
        err = ex.error();
    else
        dput(ex.value());

    free((char *) path);
    return err;
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

    f = open_vfs_with_flags(dirfd, pathname, LOOKUP_NOFOLLOW);
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
    return st;
}

ssize_t sys_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    return sys_readlinkat(AT_FDCWD, pathname, buf, bufsiz);
}

mode_t sys_umask(mode_t mask)
{
    struct process *current = get_current_process();
    spin_lock(&current->fs->cwd_lock);
    mode_t old = current->fs->umask;
    WRITE_ONCE(current->fs->umask, mask & 0777);
    spin_unlock(&current->fs->cwd_lock);
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

    int open_flags = (flags & AT_SYMLINK_NOFOLLOW ? LOOKUP_NOFOLLOW : 0);
    auto_file f = open_vfs_with_flags(dirfd, path.data(), open_flags);

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
            clock_gettime_kernel(CLOCK_REALTIME, &ktimes[i]);
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
    if (times)
    {

        if (copy_from_user(ktimes, times, sizeof(ktimes)) < 0)
            return -EFAULT;
    }
    else
    {
        ktimes[0].tv_nsec = ktimes[1].tv_nsec = UTIME_NOW;
    }

    auto_file dir;

    auto_file f;
    if (pathname)
    {
        int open_flags = (flags & AT_SYMLINK_NOFOLLOW ? LOOKUP_NOFOLLOW : 0);
        f = open_vfs_with_flags(dirfd, path.data(), open_flags);

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
        f = get_file_description(dirfd);
        if (!f)
            return -errno;
    }
    else
    {
        int open_flags = (flags & AT_SYMLINK_NOFOLLOW ? LOOKUP_NOFOLLOW : 0);
        f = open_vfs_with_flags(dirfd, pathname, open_flags);
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

    auto_file f = open_vfs(AT_FDCWD, path.data());
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
static struct slab_cache *fdtable_cache = nullptr;

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
    call_rcu(&file->rcuhead, [](struct rcu_head *head) {
        struct file *f = container_of(head, struct file, rcuhead);
        kmem_cache_free(file_cache, (void *) f);
    });
}

/**
 * @brief Allocate a struct fd_table
 *
 * @return Pointer to struct fd_table, or nullptr
 */
static fd_table *fdtable_alloc()
{
    auto table = (fd_table *) kmem_cache_alloc(fdtable_cache, GFP_KERNEL);
    if (table)
        memset(table, 0, sizeof(*table));
    return table;
}

/**
 * @brief Free a struct fd_table
 *
 * @arg file Pointer to struct fd_table
 */
void fdtable_free(struct fd_table *table)
{
    kmem_cache_free(fdtable_cache, (void *) table);
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
    fdtable_cache = kmem_cache_create("fdtable", sizeof(fd_table), 0, 0, nullptr);
    if (!fdtable_cache)
        panic("Could not allocate slab cache for struct fd_table");
}
