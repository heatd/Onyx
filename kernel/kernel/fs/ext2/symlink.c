/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include <onyx/vfs.h>

#include "ext2.h"

/* According to Linux and e2fs, this is how you detect fast symlinks */
bool ext2_is_fast_symlink(struct ext2_inode *inode, ext2_fs_t *fs)
{
	int ea_blocks = inode->file_acl ? (fs->block_size >> 9) : 0;
	return (inode->i_blocks - ea_blocks == 0 && EXT2_CALCULATE_SIZE64(inode) <= 60);
}

#define EXT2_FAST_SYMLINK_SIZE			60

char *ext2_do_fast_symlink(struct ext2_inode *inode)
{
	/* Fast symlinks have 60 bytes and we allocate one more for the null byte */
	char *buf = malloc(EXT2_FAST_SYMLINK_SIZE + 1);
	if(!buf)
		return NULL;
	memcpy(buf, &inode->dbp, EXT2_FAST_SYMLINK_SIZE);
	buf[EXT2_FAST_SYMLINK_SIZE] = '\0';
	/* TODO: Is it possible to trim this string? And should we? */
	return buf;
}

char *ext2_do_slow_symlink(struct ext2_inode *inode, ext2_fs_t *fs)
{
	size_t len = EXT2_CALCULATE_SIZE64(inode);
	char *buf = malloc(len + 1);
	if(!buf)
		return NULL;
	
	if(ext2_read_inode(inode, fs, len, 0, buf) != (ssize_t) len)
	{
		free(buf);
		return NULL;
	}

	buf[len] = '\0';

	return buf;
}

char *ext2_read_symlink(struct ext2_inode *ino, ext2_fs_t *fs)
{
	if(ext2_is_fast_symlink(ino, fs))
	{
		return ext2_do_fast_symlink(ino);
	}
	else
	{
		return ext2_do_slow_symlink(ino, fs);
	}
}

char *ext2_readlink(struct inode *ino)
{
	struct ext2_inode *ext2_ino = ext2_get_inode_from_node(ino);
	ext2_fs_t *fs = ino->i_sb->s_helper;

	return ext2_read_symlink(ext2_ino, fs);
}