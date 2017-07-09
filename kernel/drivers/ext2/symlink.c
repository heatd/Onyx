/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include <drivers/ext2.h>
/* According to Linux and e2fs, this is how you detect fast symlinks */
bool ext2_is_fast_symlink(inode_t *inode, ext2_fs_t *fs)
{
	int ea_blocks = inode->file_acl ? (fs->block_size >> 9) : 0;
	return (inode->disk_sects - ea_blocks == 0 && EXT2_CALCULATE_SIZE64(inode) <= 60);
}
char *ext2_do_fast_symlink(inode_t *inode)
{
	char *buf = malloc(60);
	if(!buf)
		return NULL;
	memcpy(buf, &inode->dbp, 60);
	return buf;
}
char *ext2_do_slow_symlink(inode_t *inode, ext2_fs_t *fs)
{
	char *buf = malloc(EXT2_CALCULATE_SIZE64(inode));
	if(!buf)
		return NULL;
	ext2_read_inode(inode, fs, EXT2_CALCULATE_SIZE64(inode), 0, buf);
	return buf;
}
char *ext2_read_symlink(inode_t *inode, ext2_fs_t *fs)
{
	if(ext2_is_fast_symlink(inode, fs))
	{
		return ext2_do_fast_symlink(inode);
	}
	else
	{
		return ext2_do_slow_symlink(inode, fs);
	}
}
inode_t *ext2_follow_symlink(inode_t *inode, ext2_fs_t *fs, inode_t *parent, uint32_t *inode_num, char **symlink)
{
	char *path = ext2_read_symlink(inode, fs);
	if(!path)
		return NULL;
	if(symlink) *symlink = strdup(path);
	char *orig_path = path;
	char *saveptr = NULL;
	char *inode_data = malloc(EXT2_CALCULATE_SIZE64(parent));
	if(!inode_data)
	{
		free(orig_path);
		return NULL;
	}
	if(ext2_read_inode(parent, fs, EXT2_CALCULATE_SIZE64(parent), 0, inode_data) != (ssize_t) EXT2_CALCULATE_SIZE64(parent))
	{
		free(orig_path);
		free(inode_data);
		return NULL;
	}
	inode_t *ino = parent;
	dir_entry_t *dir = (dir_entry_t*) inode_data;
	/* Open through the path */
	path = strtok_r(orig_path, "/", &saveptr);
	while(path)
	{
		ino = ext2_get_inode_from_dir(fs, dir, path, inode_num);
		if(!ino)
			return errno = ENOENT, NULL;
		//assert(EXT2_CALCULATE_SIZE64(ino));
		inode_data = realloc(inode_data, EXT2_CALCULATE_SIZE64(ino));
		if(!inode_data)
			return errno = ENOMEM, NULL;
		ext2_read_inode(ino, fs, EXT2_CALCULATE_SIZE64(ino), 0, inode_data);
		dir = (dir_entry_t*) inode_data;
		/* Get the next path segment */
		path = strtok_r(NULL, "/", &saveptr);
		if(path)
			free(ino);
	}
	free(inode_data);
	return ino;
}
