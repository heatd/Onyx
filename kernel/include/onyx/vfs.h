/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_VFS_H
#define _ONYX_VFS_H

#include <dirent.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#include <onyx/object.h>
#include <onyx/public/socket.h>
#include <onyx/rwlock.h>
#include <onyx/superblock.h>
#include <onyx/vm.h>

#define VFS_TYPE_FILE         (1 << 0)
#define VFS_TYPE_DIR          (1 << 1)
#define VFS_TYPE_SYMLINK      (1 << 2)
#define VFS_TYPE_MOUNTPOINT   (1 << 3)
#define VFS_TYPE_CHAR_DEVICE  (1 << 4)
#define VFS_TYPE_BLOCK_DEVICE (1 << 5)
#define VFS_TYPE_FIFO         (1 << 6)
#define VFS_TYPE_UNIX_SOCK    (1 << 7)
#define VFS_TYPE_UNK          (1 << 8)

struct inode;
struct file;
struct dentry;

typedef size_t (*__read)(size_t offset, size_t sizeofread, void *buffer, struct file *file);
typedef size_t (*__write)(size_t offset, size_t sizeofwrite, void *buffer, struct file *file);
typedef void (*__close)(struct inode *file);
typedef struct inode *(*__open)(struct dentry *dir, const char *name);
typedef off_t (*__getdirent)(struct dirent *buf, off_t off, struct file *file);
typedef unsigned int (*__ioctl)(int request, void *argp, struct file *file);
typedef struct inode *(*__creat)(const char *name, int mode, struct dentry *dir);
typedef int (*__stat)(struct stat *buf, struct file *node);
typedef struct inode *(*__symlink)(const char *name, const char *linkpath, struct dentry *dir);
typedef unsigned int (*putdir_t)(struct dirent *, struct dirent *ubuf, unsigned int count);

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
    void *(*mmap)(struct vm_region *area, struct file *node);
    int (*ftruncate)(size_t length, struct file *node);
    struct inode *(*mkdir)(const char *name, mode_t mode, struct dentry *dir);
    struct inode *(*mknod)(const char *name, mode_t mode, dev_t dev, struct dentry *dir);
    int (*on_open)(struct file *node);
    short (*poll)(void *poll_file, short events, struct file *node);
    char *(*readlink)(struct file *ino);
    int (*unlink)(const char *name, int flags, struct dentry *dir);
    int (*fallocate)(int mode, off_t offset, off_t len, struct file *node);
    ssize_t (*readpage)(struct page *page, size_t offset, struct inode *ino);
    ssize_t (*writepage)(struct page *page, size_t offset, struct inode *ino);
    int (*prepare_write)(struct inode *ino, struct page *page, size_t page_off, size_t offset,
                         size_t len);
};

struct getdents_ret
{
    int read;
    off_t new_off;
};

int inode_init(struct inode *ino, bool is_reg);

struct inode
{
    unsigned long i_refc{1};
    /* TODO: We could use a lock here to protect i_flags to have
     * thread-safe dirties, etc...
     */
    unsigned int i_flags{0};
    ino_t i_inode{0};
    gid_t i_gid{0};
    uid_t i_uid{0};
    mode_t i_mode{0};
    int i_type{0};
    size_t i_size{0};
    dev_t i_dev{0};
    dev_t i_rdev{0};
    time_t i_atime{0};
    time_t i_ctime{0};
    time_t i_mtime{0};
    nlink_t i_nlink{0};
    blkcnt_t i_blocks{0};
    struct superblock *i_sb{nullptr};

    struct file_ops *i_fops{nullptr};

    struct vm_object *i_pages{nullptr};
    struct list_head i_dirty_inode_node;
    void *i_flush_dev{nullptr};

    struct inode *i_next{nullptr};
    void *i_helper{nullptr};
    struct dentry *i_dentry{nullptr}; /* Only valid for directories */
    struct rwlock i_rwlock;
    struct list_head i_sb_list_node;
    struct list_head i_hash_list_node;

#ifdef __cplusplus

    inode()
    {
        rwlock_init(&i_rwlock);
    }

    int init(mode_t mode)
    {
        return inode_init(this, S_ISREG(mode));
    }
#endif
};

struct dentry;

struct file
{
#ifndef __cplusplus
    _Atomic
#endif
        unsigned long f_refcount;
    off_t f_seek;
    struct inode *f_ino;
    unsigned int f_flags;
    struct dentry *f_dentry;
};

#define INODE_FLAG_DONT_CACHE (1 << 0)
#define INODE_FLAG_DIRTY      (1 << 1)
#define INODE_FLAG_NO_SEEK    (1 << 2)
#define INODE_FLAG_DIRTYING   (1 << 3)

int inode_create_vmo(struct inode *ino);

#define OPEN_FLAG_NOFOLLOW     (1 << 0)
#define OPEN_FLAG_FAIL_IF_LINK (1 << 1)
#define OPEN_FLAG_MUST_BE_DIR  (1 << 2)
#define LOOKUP_FLAG_INTERNAL_TRAILING_SLASH \
    (1 << 3) /* Might be useful for callers \
              * that handle the last name.  \
              */

#define OPEN_FLAG_EMPTY_PATH                              \
    (1 << 4) /* Used to implement AT_EMPTY_PATH,          \
              * makes open routines return the base file. \
              */
struct file *open_vfs_with_flags(struct file *dir, const char *path, unsigned int flags);
struct file *open_vfs(struct file *dir, const char *path);

ssize_t read_vfs(size_t offset, size_t length, void *buffer, struct file *file);

ssize_t write_vfs(size_t offset, size_t length, void *buffer, struct file *file);

void inode_ref(struct inode *ino);
void inode_unref(struct inode *ino);

void close_vfs(struct inode *ino);

struct file *creat_vfs(struct dentry *node, const char *path, int mode);

int getdents_vfs(unsigned int count, putdir_t putdir, struct dirent *dirp, off_t off,
                 struct getdents_ret *ret, struct file *file);

int ioctl_vfs(int request, char *argp, struct file *file);

int stat_vfs(struct stat *buf, struct file *node);

int ftruncate_vfs(off_t length, struct file *vnode);

struct file *mkdir_vfs(const char *path, mode_t mode, struct dentry *node);

struct file *symlink_vfs(const char *path, const char *dest, struct dentry *inode);

int mount_fs(struct inode *node, const char *mp);

int vfs_init(void);

struct inode *inode_create(bool is_cached);

struct file *get_fs_root(void);

short poll_vfs(void *poll_file, short events, struct file *node);

int fallocate_vfs(int mode, off_t offset, off_t len, struct file *file);

struct file *mknod_vfs(const char *path, mode_t mode, dev_t dev, struct dentry *file);

struct file *get_current_directory(void);

int link_vfs(struct file *target, struct file *rel_base, const char *newpath);

#define UNLINK_VFS_DONT_TEST_EMPTY (1 << 24)

int unlink_vfs(const char *name, int flags, struct file *node);

char *readlink_vfs(struct file *file);

struct file *get_fs_base(const char *file, struct file *rel_base);

void inode_mark_dirty(struct inode *ino);

int inode_flush(struct inode *ino);

int inode_special_init(struct inode *ino);

/**
 * @brief Test if the inode requires special handling.
 * The only inode types that require special handling are chr/blk devices,
 * fifos and sockets.
 *
 * @param ino Pointer to the inode
 * @return True if special, else false
 */
static inline bool inode_is_special(inode *ino)
{
    auto mode = ino->i_mode;
    if (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode))
        return false;
    else
        return true;
}

#define FILE_ACCESS_READ    (1 << 0)
#define FILE_ACCESS_WRITE   (1 << 1)
#define FILE_ACCESS_EXECUTE (1 << 2)

bool inode_can_access(struct inode *file, unsigned int perms);
bool file_can_access(struct file *file, unsigned int perms);

struct page_cache_block;
struct page_cache_block *inode_get_page(struct inode *inode, off_t offset, long flags);

struct file *inode_to_file(struct inode *ino);
int inode_truncate_range(struct inode *inode, size_t start, size_t end);

struct filesystem_root
{
    struct object object;
    struct file *file;
};

struct filesystem_root *get_filesystem_root(void);

/* Although tbh, vfs_type should be irradicated */
static inline int mode_to_vfs_type(mode_t mode)
{
    if (S_ISREG(mode))
        return VFS_TYPE_FILE;
    else if (S_ISBLK(mode))
        return VFS_TYPE_BLOCK_DEVICE;
    else if (S_ISCHR(mode))
        return VFS_TYPE_CHAR_DEVICE;
    else if (S_ISFIFO(mode))
        return VFS_TYPE_FIFO;
    else if (S_ISLNK(mode))
        return VFS_TYPE_SYMLINK;
    else if (S_ISSOCK(mode))
        return VFS_TYPE_UNIX_SOCK;
    else if (S_ISDIR(mode))
        return VFS_TYPE_DIR;
    else
        __builtin_unreachable();
}

/* Must be called with i_rwlock held */
static inline void inode_set_size(struct inode *ino, size_t size)
{
    ino->i_size = size;
    ino->i_pages->size = (size_t) page_align_up((void *) size);
    inode_mark_dirty(ino);
}

static inline void inode_inc_nlink(struct inode *ino)
{
    __atomic_add_fetch(&ino->i_nlink, 1, __ATOMIC_RELAXED);
    inode_mark_dirty(ino);
}

static inline void inode_dec_nlink(struct inode *ino)
{
    __atomic_sub_fetch(&ino->i_nlink, 1, __ATOMIC_RELAXED);
    inode_mark_dirty(ino);
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

/**
 * @brief Getdirent helper
 *
 * @param buf Pointer to struct dirent
 * @param dentry Pointer to dentry
 * @param special_name Special name if the current dentry is "." or ".."
 */
void put_dentry_to_dirent(struct dirent *buf, dentry *dentry, const char *special_name = nullptr);

/**
 * @brief Applies setuid and setgid permissions
 *
 * @param f File
 * @return True if applied, else false
 */
bool apply_sugid_permissions(file *f);

#endif
