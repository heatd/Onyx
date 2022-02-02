/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <stdio.h>

#include <onyx/pseudo.h>

#if 0
static struct file_ops pseudo_ops = 
{
};

struct file *pseudo_to_inode(struct pseudo_file *file)
{
	struct inode *inode = inode_create(false);
	if(!inode)
		return NULL;
	inode->i_dev = (dev_t) file->mount;
	inode->i_inode = (ino_t) file;

	memcpy(&inode->i_fops, &pseudo_ops, sizeof(struct file_ops));

	return inode;
}

struct pseudo_mount *pseudo_create_mount(const char *mountpath, int mode)
{
	struct pseudo_mount *m = zalloc(sizeof(*m));
	if(!m)
		return NULL;

	m->root = zalloc(sizeof(*m->root));
	if(!m->root)
	{
		free(m);
		return NULL;
	}

	m->root->mode = mode;
	m->root->file_type = VFS_TYPE_DIR;
	m->root->mount = m;

	struct superblock *sb = zalloc(sizeof(*sb));
	if(!sb)
	{
		free(m->root);
		free(m);
		return NULL;
	}

	sb->s_ref = 1;

	m->sb = sb;

	struct file *inode = pseudo_to_inode(m->root);
	if(!inode)
	{
		free(sb);
		free(m->root);
		free(m);
		return NULL;
	}

	if(mount_fs(inode, mountpath) < 0)
	{
		free(sb);
		free(inode);
		free(m->root);
		free(m);
		return NULL;
	}

	printf("pseudofs: Mounted new pseudofs %s\n", mountpath);
	return 0;
}

void pseudo_add_file(struct pseudo_file *dir, struct pseudo_file *file)
{}
void pseudo_rm_file(struct pseudo_file *file);

#endif
