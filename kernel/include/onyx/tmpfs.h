/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_TMPFS_H
#define _KERNEL_TMPFS_H

#include <onyx/mutex.h>
#include <onyx/vfs.h>

#include <sys/types.h>

#define TMPFS_FILE_TYPE_DIR	(1 << 0)
#define TMPFS_FILE_TYPE_REG	(1 << 1)
#define TMPFS_FILE_TYPE_SYM	(1 << 2)
#define TMPFS_FILE_TYPE_CHAR	(1 << 3)
#define TMPFS_FILE_TYPE_BLOCK	(1 << 4)

typedef struct data_blk
{
	struct data_blk *next;
	char data[0];
} tmpfs_data_block_t;

typedef struct tmpfs_file
{
	const char *name;
	size_t size;
	uid_t st_uid;
	gid_t st_gid;
	mode_t mode;
	dev_t rdev;
	unsigned int type;
	const char *symlink;
	tmpfs_data_block_t *data;
	mutex_t dirent_lock;
	mutex_t data_lock;
	struct tmpfs_file *sibblings;
	struct tmpfs_file *parent;
	struct tmpfs_file *child;
} tmpfs_file_t;

typedef struct tmpfs_filesystem
{
	struct tmpfs_filesystem *next;
	tmpfs_file_t *root;
	struct superblock *superblock;
} tmpfs_filesystem_t;

tmpfs_filesystem_t *tmpfs_get_root(struct inode *inode);
int tmpfs_mount(const char *mountpoint);
int tmpfs_fill_with_data(struct inode *vnode, const void *buf, size_t size);
tmpfs_file_t *tmpfs_create_file(tmpfs_file_t *dir, const char *name);
struct inode *tmpfs_file_to_vfs(tmpfs_file_t *file, struct inode *parent);

#endif
