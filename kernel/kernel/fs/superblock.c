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
	spin_lock(&sb->s_ilock);
	for(struct inode *ino = sb->s_inodes; ino; ino = ino->i_next)
	{
		if(ino->i_inode == inode)
		{
			object_ref(&ino->i_object);
			spin_unlock(&sb->s_ilock);
			return ino;
		}
	}

	return NULL;
}

void superblock_add_inode_unlocked(struct superblock *sb, struct inode *inode)
{
	/* FIXME: O(n) time complexity on adding to a linked list - nasty and
	 * possibly a war crime in multiple countries
	*/
	struct inode **ino = &sb->s_inodes;

	while(*ino)
	{
		ino = &(*ino)->i_next;
	}
	*ino = inode;

	atomic_inc(&sb->s_ref, 1);

	object_ref(&inode->i_object);
}

void superblock_add_inode(struct superblock *sb, struct inode *inode)
{
	spin_lock(&sb->s_ilock);

	superblock_add_inode_unlocked(sb, inode);

	spin_unlock(&sb->s_ilock);
}

void superblock_remove_inode(struct superblock *sb, struct inode *inode)
{
	spin_lock(&sb->s_ilock);

	if(sb->s_inodes == inode)
	{
		sb->s_inodes = inode->i_next;
		goto getout;
	}

	for(struct inode *ino = sb->s_inodes; ino->i_next; ino = ino->i_next)
	{
		if(ino->i_next == inode)
		{
			ino->i_next = inode->i_next;
			goto getout;
		}
	}
getout:
	atomic_dec(&sb->s_ref, 1);
	spin_unlock(&sb->s_ilock);
}
