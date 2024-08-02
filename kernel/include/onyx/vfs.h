/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_VFS_H
#define _ONYX_VFS_H

#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include <onyx/flock.h>
#include <onyx/inode.h>
#include <onyx/iovec_iter.h>
#include <onyx/mm/vm_object.h>
#include <onyx/object.h>
#include <onyx/path.h>
#include <onyx/rcupdate.h>
#include <onyx/rwlock.h>
#include <onyx/superblock.h>
#include <onyx/vm.h>

#include <uapi/dirent.h>
#include <uapi/fcntl.h>
#include <uapi/stat.h>

struct inode;
struct file;
struct dentry;
struct iovec_iter;
struct readpages_state;

__BEGIN_CDECLS

struct dentry;

struct readahead_state
{
    /* All values below are in pages, not bytes */
    unsigned long ra_start;
    unsigned long ra_window;
    unsigned long ra_mark;
};

static inline void ra_state_init(struct readahead_state *ra)
{
    ra->ra_start = ra->ra_mark = ra->ra_window = 0;
}

/* Our max readahead window will be 512KiB (in however many pages). The window cannot grow from
 * there. */
#define RA_MAX_WINDOW (0x80000 / PAGE_SIZE)

struct file
{
    unsigned long f_refcount;
    off_t f_seek;
    struct inode *f_ino;
    struct path f_path;
#define f_dentry f_path.dentry
    union {
        void *private_data;
        struct rcu_head rcuhead;
    };
    struct mutex f_seeklock;
    unsigned int f_flags;
    struct readahead_state f_ra_state;
    struct flock_file_info *f_flock;
};

int inode_create_vmo(struct inode *ino);

struct file *open_vfs_with_flags(int dirfd, const char *path, unsigned int flags);
struct file *open_vfs(int dirfd, const char *path);

ssize_t read_vfs(size_t offset, size_t length, void *buffer, struct file *file);

ssize_t write_vfs(size_t offset, size_t length, void *buffer, struct file *file);

void inode_ref(struct inode *ino);
void inode_unref(struct inode *ino);

void close_vfs(struct inode *ino);

int getdents_vfs(unsigned int count, putdir_t putdir, struct dirent *dirp, off_t off,
                 struct getdents_ret *ret, struct file *file);

int ioctl_vfs(int request, char *argp, struct file *file);

int stat_vfs(struct stat *buf, struct file *node);

int ftruncate_vfs(off_t length, struct file *vnode);

int symlink_vfs(const char *path, const char *dest, int dirfd);

int vfs_init(void);

struct inode *inode_create(bool is_cached);

short poll_vfs(void *poll_file, short events, struct file *node);

int fallocate_vfs(int mode, off_t offset, off_t len, struct file *file);

#define UNLINK_VFS_DONT_TEST_EMPTY (1 << 24)

int unlink_vfs(const char *path, int flags, int dirfd);

char *readlink_vfs(struct file *file);

/* C does not support default args... */
#ifdef __cplusplus
void inode_mark_dirty(struct inode *ino, unsigned int flags = I_DIRTY);
#else
void inode_mark_dirty(struct inode *ino, unsigned int flags);
#endif

int inode_special_init(struct inode *ino);

/**
 * @brief Test if the inode requires special handling.
 * The only inode types that require special handling are chr/blk devices,
 * fifos and sockets.
 *
 * @param ino Pointer to the inode
 * @return True if special, else false
 */
static inline bool inode_is_special(struct inode *ino)
{
    mode_t mode = ino->i_mode;
    if (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode))
        return false;
    else
        return true;
}

__always_inline void inode_lock(struct inode *ino)
{
    rw_lock_write(&ino->i_rwlock);
}

__always_inline void inode_unlock(struct inode *ino)
{
    rw_unlock_write(&ino->i_rwlock);
}

__always_inline void inode_lock_shared(struct inode *ino)
{
    rw_lock_read(&ino->i_rwlock);
}

__always_inline void inode_unlock_shared(struct inode *ino)
{
    rw_unlock_read(&ino->i_rwlock);
}

#define FILE_ACCESS_READ    (1 << 0)
#define FILE_ACCESS_WRITE   (1 << 1)
#define FILE_ACCESS_EXECUTE (1 << 2)

bool inode_can_access(struct inode *file, unsigned int perms);
bool file_can_access(struct file *file, unsigned int perms);
bool fd_may_access(struct file *f, unsigned int access);

struct file *inode_to_file(struct inode *ino);
int inode_truncate_range(struct inode *inode, size_t start, size_t end);

struct path get_filesystem_root(void);

int path_openat(int dirfd, const char *name, unsigned int flags, struct path *path);

/* Must be called with i_rwlock held */
static inline void inode_set_size(struct inode *ino, size_t size)
{
    ino->i_size = size;
    ino->i_pages->size = size;
    inode_mark_dirty(ino, I_DIRTY);
}

static inline void inode_inc_nlink(struct inode *ino)
{
    __atomic_add_fetch(&ino->i_nlink, 1, __ATOMIC_RELAXED);
    inode_mark_dirty(ino, I_DIRTY);
}

static inline void inode_dec_nlink(struct inode *ino)
{
    __atomic_sub_fetch(&ino->i_nlink, 1, __ATOMIC_RELAXED);
    inode_mark_dirty(ino, I_DIRTY);
}

static inline nlink_t inode_get_nlink(struct inode *ino)
{
    return __atomic_load_n(&ino->i_nlink, __ATOMIC_RELAXED);
}

/* Called when the inode's references = 0 */
static inline bool inode_should_die(struct inode *ino)
{
    return inode_get_nlink(ino) == 0;
}

void inode_unlock_hashtable(struct superblock *sb, ino_t ino_nr);

void inode_update_atime(struct inode *ino);
void inode_update_ctime(struct inode *ino);
void inode_update_mtime(struct inode *ino);

#ifdef __cplusplus
/**
 * @brief Getdirent helper
 *
 * @param buf Pointer to struct dirent
 * @param dentry Pointer to dentry
 * @param special_name Special name if the current dentry is "." or ".."
 */
void put_dentry_to_dirent(struct dirent *buf, struct dentry *dentry,
                          const char *special_name = nullptr);

extern "C++"
{
expected<dentry *, int> creat_vfs(int dirfd, const char *path, int mode);
expected<dentry *, int> mknod_vfs(const char *path, mode_t mode, dev_t dev, int dirfd);
expected<dentry *, int> mkdir_vfs(const char *path, mode_t mode, int dirfd);
}
#endif

/**
 * @brief Applies setuid and setgid permissions
 *
 * @param f File
 * @return True if applied, else false
 */
bool apply_sugid_permissions(struct file *f);

/**
 * @brief Trim the inode cache
 *
 */
void inode_trim_cache();

int file_close(int fd);

/**
 * @brief Write to a file using iovec_iter
 *
 * @param filp File pointer
 * @param off Offset
 * @param iter Iterator
 * @param flags Flags
 * @return Written bytes, or negative error code
 */
ssize_t write_iter_vfs(struct file *filp, size_t off, struct iovec_iter *iter, unsigned int flags);

/**
 * @brief Read from a file using iovec_iter
 *
 * @param filp File pointer
 * @param off Offset
 * @param iter Iterator
 * @param flags Flags
 * @return Read bytes, or negative error code
 */
ssize_t read_iter_vfs(struct file *filp, size_t off, struct iovec_iter *iter, unsigned int flags);

int noop_prepare_write(struct inode *ino, struct page *page, size_t page_off, size_t offset,
                       size_t len);

void inode_wait_writeback(struct inode *ino);
bool inode_no_dirty(struct inode *ino, unsigned int flags);

int set_root(struct path *path);

__END_CDECLS

#endif
