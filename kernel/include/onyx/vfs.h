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

#define VFS_TYPE_FILE 		(1 << 0)
#define VFS_TYPE_DIR 		(1 << 1)
#define VFS_TYPE_SYMLINK 	(1 << 2)
#define VFS_TYPE_MOUNTPOINT 	(1 << 3)
#define VFS_TYPE_CHAR_DEVICE 	(1 << 4)
#define VFS_TYPE_BLOCK_DEVICE 	(1 << 5)
#define VFS_TYPE_FIFO		(1 << 6)
#define VFS_TYPE_UNIX_SOCK	(1 << 7)
#define VFS_TYPE_UNK		(1 << 8)

#define VFS_PAGE_HASHTABLE_ENTRIES	(PAGE_SIZE / sizeof(uintptr_t))

struct inode;
struct dev;
struct dentry;

typedef size_t (*__read)(int flags, size_t offset, size_t sizeofread, void* buffer, struct inode* file);
typedef size_t (*__write)(size_t offset, size_t sizeofwrite, void* buffer, struct inode* file);
typedef void (*__close)(struct inode* file);
typedef struct inode *(*__open)(struct inode* file, const char *name);
typedef off_t (*__getdirent)(struct dirent *buf, off_t off, struct inode* file);
typedef unsigned int (*__ioctl)(int request, void *argp, struct inode* file);
typedef struct inode *(*__creat)(const char *pathname, int mode, struct inode *file);
typedef int (*__stat)(struct stat *buf, struct inode *node);
typedef int (*__symlink)(const char *linkpath, struct inode *node);
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
	int (*link)(struct inode *target_ino, const char *name, struct inode *dir);
	__symlink symlink;
	void *(*mmap)(struct vm_region *area, struct inode *node);
	int (*bind)(const struct sockaddr *addr, socklen_t addrlen, struct inode *vnode);
	int (*connect)(const struct sockaddr *addr, socklen_t addrlen, struct inode *vnode);
	ssize_t (*sendto)(const void *buf, size_t len, int flags,
		struct sockaddr *addr, socklen_t addrlen, struct inode *vnode);
	ssize_t (*recvfrom)(void *buf, size_t len, int flags, struct sockaddr *addr, 
		socklen_t *slen, struct inode *vnode);
	int (*ftruncate)(off_t length, struct inode *node);
	struct inode *(*mkdir)(const char *name, mode_t mode, struct inode *node);
	struct inode *(*mknod)(const char *name, mode_t mode, dev_t dev, struct inode *node);
	int (*on_open)(struct inode *node);
	short (*poll)(void *poll_file, short events, struct inode *node);
	char *(*readlink)(struct inode *ino);
	int (*unlink)(const char *name, int flags, struct inode *node);
};

struct getdents_ret
{
	int read;
	off_t new_off;
};

struct inode
{
	struct object i_object;
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
	struct superblock *i_sb;
	/* TODO: Make i_fops be a pointer instead of being embedded in inode, to save memory */
	struct file_ops i_fops;

	struct spinlock i_pages_lock;
	struct vm_object *i_pages;
	
	struct inode *i_next;
	struct inode *i_link;
	void *i_helper;
};

#if 0
struct file
{
	struct object object;
	struct inode *inode;
	struct dentry *dentry;
};
/* TODO */

#endif


#ifdef __cplusplus
extern "C" {
#endif

int inode_create_vmo(struct inode *ino);

struct page_cache_block *add_cache_to_node(void *ptr, size_t size, off_t offset, struct inode *node);

struct inode *open_vfs(struct inode *dir, const char *path);

#define READ_VFS_FLAG_IS_PAGE_CACHE		(1 << 20)

size_t read_vfs(int flags, size_t offset, size_t sizeofread, void* buffer,
	struct inode* file);

size_t write_vfs(size_t offset, size_t sizeofwrite, void* buffer,
	struct inode* file);

void close_vfs(struct inode* file);

struct inode *creat_vfs(struct inode *node, const char *path, int mode);

int getdents_vfs(unsigned int count, putdir_t putdir, struct dirent* dirp,
	off_t off, struct getdents_ret *ret, struct inode *file);

int ioctl_vfs(int request, char *argp, struct inode *file);

int stat_vfs(struct stat *buf, struct inode *node);

ssize_t sendto_vfs(const void *buf, size_t len, int flags, struct sockaddr *addr,
 socklen_t addrlen, struct inode *node);

int connect_vfs(const struct sockaddr *addr, socklen_t addrlen,
	struct inode *node);

int bind_vfs(const struct sockaddr *addr, socklen_t addrlen,
	struct inode *node);

ssize_t recvfrom_vfs(void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *slen, struct inode *node);

int ftruncate_vfs(off_t length, struct inode *vnode);

struct inode *mkdir_vfs(const char *path, mode_t mode, struct inode *node);

int symlink_vfs(const char *dest, struct inode *inode);

int mount_fs(struct inode *node, const char *mp);

int vfs_init(void);

ssize_t lookup_file_cache(void *buffer, size_t sizeofread, struct inode *file,
	off_t offset);

ssize_t do_file_caching(size_t sizeofread, struct inode *ino, off_t offset,
	int flags);

struct inode *inode_create(void);

struct inode *get_fs_root(void);

short poll_vfs(void *poll_file, short events, struct inode *node);

int fallocate_vfs(int mode, off_t offset, off_t len, struct inode *file);

struct inode *mknod_vfs(const char *path, mode_t mode, dev_t dev, struct inode *file);

struct file *get_current_directory(void);

int link_vfs(struct inode *target, const char *name, struct inode *dir);

int unlink_vfs(const char *name, int flags, struct inode *node);

struct inode *get_fs_base(const char *file, struct inode *rel_base);


#define FILE_ACCESS_READ    (1 << 0)
#define	FILE_ACCESS_WRITE   (1 << 1)
#define FILE_ACCESS_EXECUTE (1 << 2)

bool file_can_access(struct inode *file, unsigned int perms);

#ifdef __cplusplus
}
#endif

#endif
