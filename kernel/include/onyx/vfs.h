/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _VFS_H
#define _VFS_H

#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <stdarg.h>

#include <onyx/object.h>
#include <onyx/vm.h>
#include <onyx/superblock.h>

#include <sys/socket.h>
#include <sys/stat.h>

#define VFS_TYPE_FILE            (1 << 0)
#define VFS_TYPE_DIR             (1 << 1)
#define VFS_TYPE_SYMLINK         (1 << 2)
#define VFS_TYPE_MOUNTPOINT      (1 << 3)
#define VFS_TYPE_CHAR_DEVICE     (1 << 4)
#define VFS_TYPE_BLOCK_DEVICE    (1 << 5)
#define VFS_TYPE_FIFO            (1 << 6)
#define VFS_TYPE_UNIX_SOCK       (1 << 7)
#define VFS_TYPE_UNK             (1 << 8)

#define VFS_PAGE_HASHTABLE_ENTRIES	(PAGE_SIZE / sizeof(uintptr_t))

struct inode;
struct file;
struct dev;
struct dentry;

typedef size_t (*__read)(size_t offset, size_t sizeofread, void* buffer, struct file* file);
typedef size_t (*__write)(size_t offset, size_t sizeofwrite, void* buffer, struct file* file);
typedef void (*__close)(struct inode *file);
typedef struct inode *(*__open)(struct dentry *dir, const char *name);
typedef off_t (*__getdirent)(struct dirent *buf, off_t off, struct file* file);
typedef unsigned int (*__ioctl)(int request, void *argp, struct file* file);
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
	int (*ftruncate)(off_t length, struct file *node);
	struct inode *(*mkdir)(const char *name, mode_t mode, struct dentry *dir);
	struct inode *(*mknod)(const char *name, mode_t mode, dev_t dev, struct dentry *dir);
	int (*on_open)(struct file *node);
	short (*poll)(void *poll_file, short events, struct file *node);
	char *(*readlink)(struct file *ino);
	int (*unlink)(const char *name, int flags, struct dentry *dir);
	int (*fallocate)(int mode, off_t offset, off_t len, struct file *node);
	ssize_t (*readpage)(struct page *page, size_t offset, struct inode *ino);
	ssize_t (*writepage)(struct page *page, size_t offset, struct inode *ino);
};

struct getdents_ret
{
	int read;
	off_t new_off;
};

struct inode
{
	struct object i_object;
	/* TODO: We could use a rwlock here to sequence reads and writes */
	unsigned int i_flags;
	ino_t i_inode;
	gid_t i_gid;
	uid_t i_uid;
	mode_t i_mode;
	int i_type;
	size_t i_size;
	dev_t i_dev;
	dev_t i_rdev;
	time_t i_atime;
	time_t i_ctime;
	time_t i_mtime;
	nlink_t i_nlink;
	struct superblock *i_sb;

	struct file_ops *i_fops;

	struct spinlock i_pages_lock;
	struct vm_object *i_pages;
	struct list_head i_dirty_inode_node;
	void *i_flush_dev;
	
	struct inode *i_next;
	void *i_helper;
	struct dentry *i_dentry; /* Only valid for directories */
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

#define INODE_FLAG_DONT_CACHE		(1 << 0)
#define INODE_FLAG_DIRTY			(1 << 1)
#define INODE_FLAG_NO_SEEK          (1 << 2)

#ifdef __cplusplus
extern "C" {
#endif

int inode_create_vmo(struct inode *ino);

#define OPEN_FLAG_NOFOLLOW                  (1 << 0)
#define OPEN_FLAG_FAIL_IF_LINK              (1 << 1)
#define OPEN_FLAG_MUST_BE_DIR               (1 << 2)
#define LOOKUP_FLAG_INTERNAL_TRAILING_SLASH (1 << 3)   /* Might be useful for callers
                                                        * that handle the last name.
														*/

#define OPEN_FLAG_EMPTY_PATH                 (1 << 4)  /* Used to implement AT_EMPTY_PATH,
                                                        * makes open routines return the base file.
														*/
struct file *open_vfs_with_flags(struct file *dir, const char *path, unsigned int flags);
struct file *open_vfs(struct file *dir, const char *path);

ssize_t read_vfs(size_t offset, size_t length, void *buffer,
	struct file* file);

ssize_t write_vfs(size_t offset, size_t length, void *buffer,
	struct file* file);

void close_vfs(struct inode* file);

struct file *creat_vfs(struct dentry *node, const char *path, int mode);

int getdents_vfs(unsigned int count, putdir_t putdir, struct dirent* dirp,
	off_t off, struct getdents_ret *ret, struct file *file);

int ioctl_vfs(int request, char *argp, struct file *file);

int stat_vfs(struct stat *buf, struct file *node);

int ftruncate_vfs(off_t length, struct file *vnode);

struct file *mkdir_vfs(const char *path, mode_t mode, struct dentry *node);

struct file *symlink_vfs(const char *path, const char *dest, struct dentry *inode);

int mount_fs(struct inode *node, const char *mp);

int vfs_init(void);

ssize_t lookup_file_cache(void *buffer, size_t sizeofread, struct inode *ino,
	off_t offset);

ssize_t do_file_caching(size_t sizeofread, struct inode *ino, off_t offset,
	int flags);

struct inode *inode_create(bool is_regular_file);

struct file *get_fs_root(void);

short poll_vfs(void *poll_file, short events, struct file *node);

int fallocate_vfs(int mode, off_t offset, off_t len, struct file *file);

struct file *mknod_vfs(const char *path, mode_t mode, dev_t dev, struct dentry *file);

struct file *get_current_directory(void);

int link_vfs(struct file *target, struct file *rel_base, const char *newpath);

int unlink_vfs(const char *name, int flags, struct file *node);

char *readlink_vfs(struct file *file);

struct file *get_fs_base(const char *file, struct file *rel_base);

void inode_mark_dirty(struct inode *ino);

int inode_flush(struct inode *ino);

#define FILE_ACCESS_READ    (1 << 0)
#define	FILE_ACCESS_WRITE   (1 << 1)
#define FILE_ACCESS_EXECUTE (1 << 2)

bool inode_can_access(struct inode *file, unsigned int perms);
bool file_can_access(struct file *file, unsigned int perms);

struct page_cache_block;
struct page_cache_block *inode_get_page(struct inode *inode, off_t offset, long flags);

struct file *inode_to_file(struct inode *ino);

struct filesystem_root
{
	struct object object;
	struct file *file;
};

struct filesystem_root *get_filesystem_root(void);


#ifdef __cplusplus
}
#endif

#endif
