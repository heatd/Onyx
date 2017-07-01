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

#include <kernel/avl.h>
#include <kernel/vmm.h>

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
struct vfsnode;
typedef size_t (*__read)(int flags, size_t offset, size_t sizeofread, void* buffer, struct vfsnode* this);
typedef size_t (*__write)(size_t offset, size_t sizeofwrite, void* buffer, struct vfsnode* this);
typedef void (*__close)(struct vfsnode* this);
typedef struct vfsnode *(*__open)(struct vfsnode* this, const char *name);
typedef unsigned int (*__getdents)(unsigned int count, struct dirent* dirp, off_t off, struct vfsnode* this);
typedef unsigned int (*__ioctl)(int request, void *argp, struct vfsnode* this);
typedef struct vfsnode *(*__creat)(const char *pathname, int mode, struct vfsnode *this);
typedef int (*__stat)(struct stat *buf, struct vfsnode *node);
typedef int (*__link)(const char *newpath, struct vfsnode *node);
typedef int (*__symlink)(const char *linkpath, struct vfsnode *node);
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
	void *(*mmap)(vmm_entry_t *area, struct vfsnode *node);
};
typedef struct vfsnode
{
	ino_t inode;
	int gid;
	int uid;
	int permitions;
	int type;
	size_t size;
	_Atomic int refcount;
	char *name;
	char *mountpoint;
	dev_t dev;
	avl_node_t *cache_tree;
	struct vfsnode *next;
	struct vfsnode *link;
} vfsnode_t;

void *add_cache_to_node(void *ptr, size_t size, off_t offset, vfsnode_t *node);
size_t read_vfs(int flags, size_t offset, size_t sizeofread, void* buffer, vfsnode_t* this);
size_t write_vfs(size_t offset, size_t sizeofwrite, void* buffer, vfsnode_t* this);
void close_vfs(vfsnode_t* this);
vfsnode_t *open_vfs(vfsnode_t* this, const char*);
int mount_fs(vfsnode_t *node, const char *mp);
vfsnode_t *creat_vfs(vfsnode_t *node, const char *path, int mode);
unsigned int getdents_vfs(unsigned int count, struct dirent* dirp, off_t off, vfsnode_t *this);
int ioctl_vfs(int request, char *argp, vfsnode_t *this);
int stat_vfs(struct stat *buf, vfsnode_t *node);
int vfs_init();
struct minor_device;
ssize_t lookup_file_cache(void *buffer, size_t sizeofread, vfsnode_t *file, struct minor_device *m, off_t offset);
char *vfs_get_full_path(vfsnode_t *vnode, char *name);
extern vfsnode_t* fs_root;
#endif
