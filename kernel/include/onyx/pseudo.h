/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_PSEUDO_H
#define _ONYX_PSEUDO_H

#include <onyx/vfs.h>
#include <onyx/superblock.h>

#define PSEUDO_FILE(inode)		((void *) inode->i_inode)

struct pseudo_mount;

struct pseudo_file
{
	char name[256];
	int mode;
	int file_type;
	/* Only applies if directory */
	struct pseudo_file *children;
	/* Only applies if file has sibblings */
	struct pseudo_file *sibbling;
	struct pseudo_file *parent;

	struct file_ops fops;

	struct pseudo_mount *mount;
};

struct pseudo_mount
{
	struct superblock *sb;
	struct pseudo_file *root;
};

struct pseudo_mount *pseudo_create_mount(const char *mountpath, int mode);
void pseudo_add_file(struct pseudo_file *dir, struct pseudo_file *file);
void pseudo_rm_file(struct pseudo_file *file);

#endif