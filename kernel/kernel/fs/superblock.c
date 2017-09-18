/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/vfs.h>
#include <onyx/superblock.h>
#include <onyx/atomic.h>

struct inode *superblock_find_inode(struct superblock *sb, ino_t inode)
{
	acquire_spinlock(&sb->s_ilock);
	for(struct inode *ino = sb->s_inodes; ino; ino = ino->next)
	{
		if(ino->inode == inode)
		{
			atomic_inc(&sb->s_ref, 1);
			atomic_inc(&ino->refcount, 1);
			release_spinlock(&sb->s_ilock);
			return ino;
		}
	}

	release_spinlock(&sb->s_ilock);
	return NULL;
}

void superblock_add_inode(struct superblock *sb, struct inode *inode)
{
	acquire_spinlock(&sb->s_ilock);

	struct inode **ino = &sb->s_inodes;

	while(*ino)
	{
		ino = &(*ino)->next;
	}
	*ino = inode;
	atomic_inc(&sb->s_ref, 1);

	release_spinlock(&sb->s_ilock);
}

void superblock_remove_inode(struct superblock *sb, struct inode *inode)
{
	acquire_spinlock(&sb->s_ilock);

	if(sb->s_inodes == inode)
	{
		sb->s_inodes = inode->next;
		goto getout;
	}

	for(struct inode *ino = sb->s_inodes; ino->next; ino = ino->next)
	{
		if(ino->next == inode)
		{
			ino->next = inode->next;
			goto getout;
		}
	}
getout:
	atomic_dec(&sb->s_ref, 1);
	release_spinlock(&sb->s_ilock);
}
