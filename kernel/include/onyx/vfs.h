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

#include <onyx/avl.h>
#include <onyx/vmm.h>

#include <sys/socket.h>
#include <sys/stat.h>

#define VFS_TYPE_FILE 		0
#define VFS_TYPE_DIR 		1
#define VFS_TYPE_SYMLINK 	(1 << 1)
#define VFS_TYPE_MOUNTPOINT 	(1 << 2)
#define VFS_TYPE_CHAR_DEVICE 	(1 << 3)
#define VFS_TYPE_BLOCK_DEVICE 	(1 << 4)
#define VFS_TYPE_FIFO		(1 << 5)
#define VFS_TYPE_UNIX_SOCK	(1 << 6)
#define VFS_TYPE_UNK		(1 << 7)

struct inode;
struct minor_device;

typedef size_t (*__read)(int flags, size_t offset, size_t sizeofread, void* buffer, struct inode* file);
typedef size_t (*__write)(size_t offset, size_t sizeofwrite, void* buffer, struct inode* file);
typedef void (*__close)(struct inode* file);
typedef struct inode *(*__open)(struct inode* file, const char *name);
typedef unsigned int (*__getdents)(unsigned int count, struct dirent* dirp, off_t off, struct inode* file);
typedef unsigned int (*__ioctl)(int request, void *argp, struct inode* file);
typedef struct inode *(*__creat)(const char *pathname, int mode, struct inode *file);
typedef int (*__stat)(struct stat *buf, struct inode *node);
typedef int (*__link)(const char *newpath, struct inode *node);
typedef int (*__symlink)(const char *linkpath, struct inode *node);

struct file_ops
{
	__read read;
	__write write;
	__open open;
	__close close;
	__getdents getdents;
	__ioctl ioctl;
	__creat creat;
	__stat stat;
	__link link;
	__symlink symlink;
	void *(*mmap)(vmm_entry_t *area, struct inode *node);
	int (*bind)(const struct sockaddr *addr, socklen_t addrlen, struct inode *vnode);
	int (*connect)(const struct sockaddr *addr, socklen_t addrlen, struct inode *vnode);
	ssize_t (*send)(const void *buf, size_t len, int flags, struct inode *vnode);
	ssize_t (*recvfrom)(void *buf, size_t len, int flags, struct sockaddr *addr, 
		socklen_t *slen, struct inode *vnode);
	int (*ftruncate)(off_t length, struct inode *node);
	struct inode *(*mkdir)(const char *name, mode_t mode, struct inode *node);
};

struct inode
{
	ino_t inode;
	int gid;
	int uid;
	int permitions;
	int type;
	size_t size;
	unsigned long refcount;
	char *name;
	char *mountpoint;
	dev_t dev;
	struct file_ops fops;
	avl_node_t *cache_tree;
	struct inode *next;
	struct inode *link;
	void *helper;
};

#ifdef __cplusplus
extern "C" {
#endif
void 		*add_cache_to_node(void *ptr, size_t size, off_t offset, struct inode *node);
size_t 		read_vfs(int flags, size_t offset, size_t sizeofread, void* buffer, struct inode* file);
size_t 		write_vfs(size_t offset, size_t sizeofwrite, void* buffer, struct inode* file);
void 		close_vfs(struct inode* file);
struct inode 	*open_vfs(struct inode* file, const char*);
int 		mount_fs(struct inode *node, const char *mp);
struct inode 	*creat_vfs(struct inode *node, const char *path, int mode);
unsigned int 	getdents_vfs(unsigned int count, struct dirent* dirp, off_t off, struct inode *file);
int 		ioctl_vfs(int request, char *argp, struct inode *file);
int 		stat_vfs(struct stat *buf, struct inode *node);
ssize_t 	send_vfs(const void *buf, size_t len, int flags, struct inode *node);
int 		connect_vfs(const struct sockaddr *addr, socklen_t addrlen, struct inode *node);
int 		bind_vfs(const struct sockaddr *addr, socklen_t addrlen, struct inode *node);
ssize_t 	recvfrom_vfs(void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *slen, struct inode *node);
int 		vfs_init(void);
ssize_t 	lookup_file_cache(void *buffer, size_t sizeofread, struct inode *file, off_t offset);
char 		*vfs_get_full_path(struct inode *vnode, char *name);
int		ftruncate_vfs(off_t length, struct inode *vnode);
struct inode 	*mkdir_vfs(const char *path, mode_t mode, struct inode *node);
#ifdef __cplusplus
}
#endif
extern struct inode* fs_root;
#endif
