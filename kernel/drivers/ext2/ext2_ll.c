/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <mbr.h>
#include <partitions.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>

#include <sys/types.h>

#include <onyx/vm.h>
#include <onyx/vfs.h>
#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/log.h>
#include <onyx/fscache.h>
#include <onyx/panic.h>

#include "../include/ext2.h"

time_t get_posix_time(void);

const unsigned int direct_block_count = 12;

void *ext2_read_block(uint32_t block_index, uint16_t blocks, ext2_fs_t *fs)
{
	size_t size = blocks * fs->block_size; /* size = nblocks * block size */
	void *buff = NULL;

	buff = malloc(size); /* Allocate a buffer */
	if(!buff)
		return NULL;
	size_t read = blkdev_read(fs->first_sector * 512 + (block_index * fs->block_size), size, buff, fs->blkdevice);
	if(read == (size_t) -1)
	{
		free(buff);
		return NULL;
	}
	return buff;
}

void ext2_read_block_raw(uint32_t block_index, uint16_t blocks, ext2_fs_t *fs, void *buffer)
{
	size_t size = blocks * fs->block_size; /* size = nblocks * block size */

	blkdev_read(fs->first_sector * 512 + (block_index * fs->block_size), size, buffer, fs->blkdevice);
}

void ext2_write_block(uint32_t block_index, uint16_t blocks, ext2_fs_t *fs, void *buffer)
{
	size_t size = blocks * fs->block_size; /* size = nblocks * block size */
	blkdev_write(fs->first_sector * 512 + (block_index * fs->block_size), size, buffer, fs->blkdevice);
}

void __ext2_update_atime(inode_t *ino, uint32_t block, ext2_fs_t *fs, inode_t *inode_table)
{
	/* Skip atime updating if the inode doesn't want to */
	if(ino->flags & EXT2_INO_FLAG_ATIME_NO_UPDT)
		return;
	/* Update atime */
	ino->atime = (uint32_t) get_posix_time();
	ext2_write_block(block, 1, fs, inode_table);
}

static inline void __ext2_update_ctime(inode_t *ino)
{
	ino->ctime = (uint32_t) get_posix_time();
}

__attribute__((no_sanitize_undefined))
inode_t *ext2_get_inode_from_number(ext2_fs_t *fs, uint32_t inode)
{
	uint32_t block_size = fs->block_size;
	uint32_t bg = (inode - 1) / fs->inodes_per_block_group;
	uint32_t index = (inode - 1) % fs->inodes_per_block_group;
	uint32_t block = (index * fs->inode_size) / block_size;
	uint32_t blockind = (index * fs->inode_size) % block_size;

	assert(bg < fs->number_of_block_groups);

	block_group_desc_t *bgd = &fs->bgdt[bg];
	inode_t *inode_table = NULL;
	inode_t *inode_block = (inode_t*)((char *) (inode_table =
		ext2_read_block(bgd->inode_table_addr + block, 1, fs)) + blockind);
	
	if(!inode_table)
		return NULL;
	
	/* Update the atime field */
	__ext2_update_atime(inode_block, bgd->inode_table_addr + block, fs, inode_table);

	inode_t *ino = malloc(fs->inode_size);

	if(!ino)
	{
		free(inode_table);
		return NULL;
	}

	memcpy(ino, inode_block, fs->inode_size);
	free(inode_table);
	return ino;
}

__attribute__((no_sanitize_undefined))
void ext2_update_inode(inode_t *ino, ext2_fs_t *fs, uint32_t inode)
{
	uint32_t block_size = fs->block_size;
	uint32_t bg = (inode - 1) / fs->inodes_per_block_group;
	uint32_t index = (inode - 1) % fs->inodes_per_block_group;
	uint32_t block = (index * fs->inode_size) / block_size;
	uint32_t blockind = (index * fs->inode_size) % block_size;
	block_group_desc_t *bgd = &fs->bgdt[bg];
	inode_t *inode_table = NULL;
	inode_t *inode_block = (inode_t*)((char *) (inode_table = ext2_read_block(bgd->inode_table_addr + block, 1, fs)) + blockind);
	if(!inode_block)
		return;

	__ext2_update_ctime(ino);
	memcpy(inode_block, ino, fs->inode_size);
	ext2_write_block(bgd->inode_table_addr + block, 1, fs, inode_table);
	free(inode_table);
}

/* Open child file dirname of the directory 'ino', following symlinks */
inode_t *ext2_open_dir(inode_t *ino, const char *dirname,
	ext2_fs_t *fs, char **symlink, uint32_t *inode_num)
{
	inode_t *inode = NULL;

	if(EXT2_GET_FILE_TYPE(ino->mode) != EXT2_INO_TYPE_DIR)
		return errno = ENOTDIR, NULL;
	dir_entry_t *dirent = malloc(EXT2_CALCULATE_SIZE64(ino));
	if(!dirent)
		return errno = ENOMEM, NULL;

	if(ext2_read_inode(ino, fs, EXT2_CALCULATE_SIZE64(ino), 0, (char*) dirent) != (ssize_t) EXT2_CALCULATE_SIZE64(ino))
	{
		free(dirent);
		return errno = EIO, NULL;
	}

	inode = ext2_get_inode_from_dir(fs, dirent, (char*) dirname, inode_num, EXT2_CALCULATE_SIZE64(ino));
	
	if(!inode)
	{	
		free(dirent);
		return errno = ENOENT, NULL;
	}

	if(EXT2_GET_FILE_TYPE(inode->mode) == EXT2_INO_TYPE_SYMLINK)
	{
		inode = ext2_follow_symlink(inode, fs, ino, inode_num, symlink);
		if(!inode)
		{
			free(dirent);
			return NULL;
		}
	}
	
	free(dirent);

	return inode;
}

inode_t *ext2_traverse_fs(inode_t *wd, const char *path, ext2_fs_t *fs, char **symlink_name, uint32_t *inode_num)
{
	char *saveptr;
	char *p;
	char *original_path;
	inode_t *ino = wd;
	/* Create a dup of the string */
	original_path = p = strdup(path);
	if(!p)
		return NULL;
	/* and tokenize it */
	p = strtok_r(p, "/", &saveptr);

	for(; p; p = strtok_r(NULL, "/", &saveptr))
	{
		ino = ext2_open_dir(ino, (const char*) p, fs, symlink_name, inode_num);
		if(!ino)
		{
			free(original_path);
			return errno = ENOENT, NULL;
		}
	}

	free(original_path);
	return ino;
}

void ext2_register_superblock_changes(ext2_fs_t *fs)
{
	blkdev_write((fs->first_sector + 2) * 512, 1024, fs->sb, fs->blkdevice);
}

void ext2_register_bgdt_changes(ext2_fs_t *fs)
{
	size_t blocks_for_bgdt = (fs->number_of_block_groups * sizeof(block_group_desc_t)) / fs->block_size;
	if((fs->number_of_block_groups * sizeof(block_group_desc_t)) % fs->block_size)
		blocks_for_bgdt++;
	if(fs->block_size == 1024)
		ext2_write_block(2, (uint16_t)blocks_for_bgdt, fs, fs->bgdt);
	else
		ext2_write_block(1, (uint16_t)blocks_for_bgdt, fs, fs->bgdt);
}

size_t ext2_calculate_dirent_size(size_t len_name)
{
	size_t dirent_size = sizeof(dir_entry_t) - (255 - len_name);

	/* Dirent sizes need to be 4-byte aligned */

	if(dirent_size % 4)
		dirent_size += 4 - dirent_size % 4;

	return dirent_size;
}

int ext2_add_direntry(const char *name, uint32_t inum, inode_t *inode, inode_t *dir, ext2_fs_t *fs)
{
	uint8_t *buffer;
	uint8_t *buf = buffer = zalloc(fs->block_size);
	if(!buf)
		return errno = ENOMEM, -1;
	
	size_t off = 0;

	dir_entry_t entry;
	
	size_t dirent_size = ext2_calculate_dirent_size(strlen(name));

	entry.inode = inum;
	entry.lsbit_namelen = strlen(name);
	entry.type_indic = 1;

	strlcpy(entry.name, name, sizeof(entry.name));

	while(true)
	{
		if(off < EXT2_CALCULATE_SIZE64(dir))
		{
			ext2_read_inode(dir, fs, fs->block_size, (size_t) off, (char*) buf);

			for(size_t i = 0; i < fs->block_size;)
			{
				dir_entry_t *e = (dir_entry_t *) buf;

				size_t actual_size = ext2_calculate_dirent_size(e->lsbit_namelen);

				if(e->size > actual_size && 
				   e->size - actual_size >= dirent_size)
				{
					dir_entry_t *d = (dir_entry_t *) (buf + actual_size);
					entry.size = e->size - actual_size;
					e->size = actual_size;
					memcpy(d, &entry, dirent_size);
					
					if(ext2_write_inode(dir, fs,
						fs->block_size, (size_t) off,
						(char*) buffer) < 0)
					{
						panic("ext2_write_inode failed\n");
						return -1;
					}
	
					free(buffer);

					return 0;
				}

				buf += e->size;
				i += e->size;
			}
		}
		else
		{
			ext2_set_inode_size(dir, EXT2_CALCULATE_SIZE64(dir) + fs->block_size);

			entry.size = fs->block_size;
			memcpy(buf, &entry, dirent_size);

			if(ext2_write_inode(dir, fs, dirent_size, (size_t) off, (char*) buf) < 0)
			{
				panic("ext2_write_inode failed\n");
				return -1;
			}

			break;
		}

		off += fs->block_size;
		buf = buffer;
	}

	free(buffer);
	return 0;
}