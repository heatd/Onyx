/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
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
#define VFS_TYPE_FILE 0
#define VFS_TYPE_DIR 1
#define VFS_TYPE_SYMLINK 3
#define VFS_TYPE_MOUNTPOINT 4
#define VFS_TYPE_DEV 5
struct vfsnode;
typedef size_t (*__read)(size_t offset, size_t sizeofread, void* buffer, struct vfsnode* this);
typedef size_t (*__write)(size_t offset, size_t sizeofwrite, void* buffer, struct vfsnode* this);
typedef void (*__close)(struct vfsnode* this);
typedef int (*__open)(uint8_t rw, struct vfsnode* this);
typedef struct vfsnode
{
	ino_t inode;
	int gid;
	int uid;
	int permitions;
	int type;
	size_t size;
	char *name;
	struct vfsnode *next;
	struct vfsnode *link;
	__read read;
	__write write;
	__open open;
	__close close;
}vfsnode_t;

size_t read_vfs(size_t offset, size_t sizeofread, void* buffer, vfsnode_t* this);
size_t write_vfs(size_t offset, size_t sizeofwrite, void* buffer, vfsnode_t* this);
void close_vfs(vfsnode_t* this);
int open_vfs(uint8_t rw, vfsnode_t* this);
struct dirent* readdir_fs(vfsnode_t* this, unsigned int index);
int vfs_init();
void vfs_fini();
vfsnode_t* vfs_findnode(const char *path);
void vfs_register_node(vfsnode_t *toBeAdded);
int vfs_destroy_node(vfsnode_t *toBeRemoved);
int vfs_allocate_fd();
extern vfsnode_t* fs_root;
#endif
