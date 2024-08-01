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
#include <onyx/iovec_iter.h>
#include <onyx/mm/vm_object.h>
#include <onyx/object.h>
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

typedef size_t (*__read)(size_t offset, size_t sizeofread, void *buffer, struct file *file);
typedef size_t (*__write)(size_t offset, size_t sizeofwrite, void *buffer, struct file *file);
typedef void (*__close)(struct inode *file);
typedef int (*__open)(struct dentry *dir, const char *name, struct dentry *dentry);
typedef off_t (*__getdirent)(struct dirent *buf, off_t off, struct file *file);
typedef unsigned int (*__ioctl)(int request, void *argp, struct file *file);
typedef struct inode *(*__creat)(struct dentry *dentry, int mode, struct dentry *dir);
typedef int (*__stat)(struct stat *buf, struct file *node);
typedef struct inode *(*__symlink)(struct dentry *dentry, const char *linkpath, struct dentry *dir);
typedef unsigned int (*putdir_t)(struct dirent *, struct dirent *ubuf, unsigned int count);

struct writepages_info
{
    /* Start and end (inclusive) of writepages */
    unsigned long start;
    unsigned long end;
    unsigned int flags;
};

/* Wait for writeback to complete (this is part of sync or fsync) */
#define WRITEPAGES_SYNC (1 << 0)

struct file_ops
{
    __read read;
    __write write;
    __open open;
    __close close;
    __getdirent getdirent;
    __ioctl ioctl;
    __creat creat;
    __stat stat;
    int (*link)(struct file *target_ino, const char *name, struct dentry *dir);
    __symlink symlink;
    void *(*mmap)(struct vm_area_struct *area, struct file *node);
    int (*ftruncate)(size_t length, struct file *node);
    struct inode *(*mkdir)(struct dentry *dentry, mode_t mode, struct dentry *dir);
    struct inode *(*mknod)(struct dentry *dentry, mode_t mode, dev_t dev, struct dentry *dir);
    int (*on_open)(struct file *node);
    short (*poll)(void *poll_file, short events, struct file *node);
    char *(*readlink)(struct file *ino);
    int (*unlink)(const char *name, int flags, struct dentry *dir);
    int (*fallocate)(int mode, off_t offset, off_t len, struct file *node);
    ssize_t (*readpage)(struct page *page, size_t offset, struct inode *ino);
    ssize_t (*writepage)(struct page *page, size_t offset, struct inode *ino);
    int (*prepare_write)(struct inode *ino, struct page *page, size_t page_off, size_t offset,
                         size_t len);
    int (*fcntl)(struct file *filp, int cmd, unsigned long arg);
    void (*release)(struct file *filp);
    ssize_t (*read_iter)(struct file *filp, size_t offset, struct iovec_iter *iter,
                         unsigned int flags);
    ssize_t (*write_iter)(struct file *filp, size_t offset, struct iovec_iter *iter,
                          unsigned int flags);
    int (*writepages)(struct inode *ino, struct writepages_info *wpinfo);
    int (*fsyncdata)(struct inode *ino, struct writepages_info *wpinfo);
    ssize_t (*directio)(struct file *file, size_t off, struct iovec_iter *iter, unsigned int flags);
    int (*readpages)(struct readpages_state *state, struct inode *ino);
    int (*rename)(struct dentry *src_parent, struct dentry *src, struct dentry *dst_dir,
                  struct dentry *dst);
};

/* For directio's flags */
#define DIRECT_IO_OP(op) ((op) << 0)

enum
{
    DIRECT_IO_READ = 0,
    DIRECT_IO_WRITE,
};

struct getdents_ret
{
    int read;
    off_t new_off;
};

int inode_init(struct inode *ino, bool is_reg);

struct pipe;

#define INODE_FLAG_DONT_CACHE (1 << 0)
#define INODE_FLAG_NO_SEEK    (1 << 2)
#define I_FREEING             (1 << 4)
#define I_DATADIRTY           (1 << 5)
#define I_DIRTY               (1 << 1)
#define I_WRITEBACK           (1 << 3)
#define I_HASHED              (1 << 7)

#define I_DIRTYALL (I_DIRTY | I_DATADIRTY)

struct inode
{
    /* Read-only/mostly fields */
    ino_t i_inode;
    gid_t i_gid;
    uid_t i_uid;
    mode_t i_mode;
    dev_t i_dev;
    dev_t i_rdev;
    struct superblock *i_sb;
    struct file_ops *i_fops;
    struct vm_object *i_pages;
    void *i_helper;
    struct dentry *i_dentry; /* Only valid for directories */
    // For FIFOs
    struct pipe *i_pipe;
    size_t i_size;
    nlink_t i_nlink;
    blkcnt_t i_blocks;
    struct list_head i_sb_list_node;
    /* Note: We can't expect that flock is too contended... */
    struct flock_info i_flock;

    /* Write-frequently fields */
    unsigned long i_refc;
    unsigned int i_flags;
    time_t i_atime;
    time_t i_ctime;
    time_t i_mtime;
    struct list_head i_dirty_inode_node;
    void *i_flush_dev;

    struct rwlock i_rwlock;
    struct list_head i_hash_list_node;
    struct spinlock i_lock;

#ifdef __cplusplus
    int init(mode_t mode)
    {
        return inode_init(this, S_ISREG(mode));
    }

    void set_evicting();
#endif
};

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
    struct dentry *f_dentry;
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

int symlink_vfs(const char *path, const char *dest, struct dentry *base);

int vfs_init(void);

struct inode *inode_create(bool is_cached);

struct file *get_fs_root(void);

short poll_vfs(void *poll_file, short events, struct file *node);

int fallocate_vfs(int mode, off_t offset, off_t len, struct file *file);

struct file *get_current_directory(void);

int link_vfs(struct file *target, struct file *rel_base, const char *newpath);

#define UNLINK_VFS_DONT_TEST_EMPTY (1 << 24)

int unlink_vfs(const char *name, int flags, struct file *node);

char *readlink_vfs(struct file *file);

struct file *get_fs_base(const char *file, struct file *rel_base);

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

struct filesystem_root
{
    struct object object;
    struct file *file;
};

struct filesystem_root *get_filesystem_root(void);

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
expected<dentry *, int> creat_vfs(dentry *base, const char *path, int mode);
expected<dentry *, int> mknod_vfs(const char *path, mode_t mode, dev_t dev, struct dentry *dir);
expected<dentry *, int> mkdir_vfs(const char *path, mode_t mode, struct dentry *dir);
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

__END_CDECLS

#endif
