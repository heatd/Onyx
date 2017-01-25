/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _VFS_H
#define _VFS_H
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <stdarg.h>
#define VFS_TYPE_FILE 		0
#define VFS_TYPE_DIR 		1
#define VFS_TYPE_SYMLINK 	(1 << 1)
#define VFS_TYPE_MOUNTPOINT 	(1 << 2)
#define VFS_TYPE_CHAR_DEVICE 	(1 << 3)
#define VFS_TYPE_BLOCK_DEVICE 	(1 << 4)
struct vfsnode;
typedef size_t (*__read)(size_t offset, size_t sizeofread, void* buffer, struct vfsnode* this);
typedef size_t (*__write)(size_t offset, size_t sizeofwrite, void* buffer, struct vfsnode* this);
typedef void (*__close)(struct vfsnode* this);
typedef struct vfsnode *(*__open)(struct vfsnode* this, const char *name);
typedef unsigned int (*__getdents)(unsigned int count, struct dirent* dirp, struct vfsnode* this);
typedef unsigned int (*__ioctl)(int request, va_list varg, struct vfsnode* this);
typedef struct vfsnode *(*__creat)(const char *pathname, int mode, struct vfsnode *this);
typedef struct vfsnode
{
	ino_t inode;
	int gid;
	int uid;
	int permitions;
	int type;
	size_t size;
	int refcount;
	char *name;
	char *mountpoint;
	dev_t dev;
	struct vfsnode *next;
	struct vfsnode *link;
	__read read;
	__write write;
	__open open;
	__close close;
	__getdents getdents;
	__ioctl ioctl;
	__creat creat;
} vfsnode_t;

size_t read_vfs(size_t offset, size_t sizeofread, void* buffer, vfsnode_t* this);
size_t write_vfs(size_t offset, size_t sizeofwrite, void* buffer, vfsnode_t* this);
void close_vfs(vfsnode_t* this);
vfsnode_t *open_vfs(vfsnode_t* this, const char*);
int mount_fs(vfsnode_t *node, const char *mp);
vfsnode_t *creat_vfs(vfsnode_t *node, const char *path, int mode);
unsigned int getdents_vfs(unsigned int count, struct dirent* dirp, vfsnode_t *this);
int ioctl_vfs(int request, va_list args, vfsnode_t *this);
int vfs_init();

extern vfsnode_t* fs_root;
#endif
