/*
* Copyright (c) 2016, 2017 Pedro Falcato
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

#include <kernel/vmm.h>
#include <kernel/vfs.h>
#include <kernel/compiler.h>
#include <kernel/dev.h>
#include <kernel/log.h>
#include <kernel/fscache.h>

#include <drivers/rtc.h>
#include <drivers/ext2.h>


#define EXT2_CALCULATE_SIZE64(ino) (((uint64_t)ino->size_hi << 32) | ino->size_lo)
const unsigned int direct_block_count = 12;
uuid_t ext2_gpt_uuid[4] = 
{
	{0x3DAF, 0x0FC6, 0x8483, 0x4772, 0x798E, 0x693D, 0x47D8, 0xE47D}, /* Linux filesystem data */
	/* I'm not sure that the following entries are used, and they're probably broken */
	{0xBCE3, 0x4F68, 0x4DB1, 0xE8CD, 0xFBCA, 0x96E7, 0xB709, 0xF984}, /* Root partition (x86-64) */
	{0xC7E1, 0x933A, 0x4F13, 0x2EB4, 0x0E14, 0xB844, 0xF915, 0xE2AE}, /* /home partition */
	{0x8425, 0x3B8F, 0x4F3B, 0x20E0, 0x1A25, 0x907F, 0x98E8, 0xA76F} /* /srv (server data) partition */
};
ext2_fs_t *fslist = NULL;
ssize_t ext2_read_inode(inode_t *ino, ext2_fs_t *fs, size_t size, off_t off, char *buffer);
ssize_t ext2_write_inode(inode_t *ino, ext2_fs_t *fs, size_t size, off_t off, char *buffer);
int ext2_stat(struct stat *buf, vfsnode_t *node);
unsigned int ext2_getdents(unsigned int count, struct dirent* dirp, off_t off, vfsnode_t* this);
void *ext2_read_block(uint32_t block_index, uint16_t blocks, ext2_fs_t *fs)
{
	size_t size = blocks * fs->block_size; /* size = nblocks * block size */
	void *buff = NULL;
	/*if((buff = fscache_try_to_find_block(fs->first_sector + ((block_index * fs->block_size) % 512), fs->blkdevice, size)))
		return buff;*/
	buff = malloc(size); /* Allocate a buffer */
	if(!buff)
		return NULL;
	memset(buff, 0, size);
	size_t read = blkdev_read(fs->first_sector * 512 + (block_index * fs->block_size), size, buff, fs->blkdevice);
	//fscache_cache_sectors(buff, fs->blkdevice, fs->first_sector + ((block_index * fs->block_size) % 512), size);
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
	/*void *buff = NULL;
	if((buff = fscache_try_to_find_block(fs->first_sector + ((block_index * fs->block_size) % 512), fs->blkdevice, size)))
	{
		memcpy(buffer, buff, size);
		return;
	}*/
	
	blkdev_read(fs->first_sector * 512 + (block_index * fs->block_size), size, buffer, fs->blkdevice);

	//fscache_cache_sectors(buffer, fs->blkdevice, fs->first_sector + ((block_index * fs->block_size) % 512), size);
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
inline void __ext2_update_ctime(inode_t *ino)
{
	ino->ctime = (uint32_t) get_posix_time();
}
inode_t *ext2_get_inode_from_number(ext2_fs_t *fs, uint32_t inode)
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
		return NULL;
	
	/* Update the atime field */
	__ext2_update_atime(inode_block, bgd->inode_table_addr + block, fs, inode_table);
	return inode_block;
}
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
inode_t *ext2_get_inode_from_dir(ext2_fs_t *fs, dir_entry_t *dirent, char *name, uint32_t *inode_number)
{
	dir_entry_t *dirs = dirent;
	while(dirs->inode && dirs->lsbit_namelen)
	{
		if(!memcmp(dirs->name, name, strlen(name)))
		{
			*inode_number = dirs->inode;
			return ext2_get_inode_from_number(fs, dirs->inode);
		}
		dirs = (dir_entry_t*)((char*)dirs + dirs->size);
	}
	return NULL;
}
size_t ext2_write(size_t offset, size_t sizeofwrite, void *buffer, vfsnode_t *node)
{
	ext2_fs_t *fs = fslist;
	inode_t *ino = ext2_get_inode_from_number(fs, node->inode);
	if(!ino)
		return errno = EINVAL, (size_t) -1;
	size_t size = ext2_write_inode(ino, fs, sizeofwrite, offset, buffer);
	if(offset + size > node->size)
	{
		ext2_set_inode_size(ino, offset + size);
		node->size = offset + size;
	}
	ext2_update_inode(ino, fs, node->inode);
	return size;
}
size_t ext2_read(int flags, size_t offset, size_t sizeofreading, void *buffer, vfsnode_t *node)
{
	/* We don't use the flags for now, only for things that might block */
	(void) flags;
	if(offset > node->size)
		return errno = EINVAL, -1;
	ext2_fs_t *fs = fslist;
	inode_t *ino = ext2_get_inode_from_number(fs, node->inode);
	if(!ino)
		return errno = EINVAL, -1;
	size_t to_be_read = offset + sizeofreading > node->size ? sizeofreading - offset - sizeofreading + node->size : sizeofreading;
	size_t size = ext2_read_inode(ino, fs, to_be_read, offset, buffer);
	return size;
}
unsigned int ext2_detect_block_type(uint32_t block, ext2_fs_t *fs)
{
	unsigned int min_singly_block = direct_block_count;
	unsigned int min_doubly_block = (fs->block_size / sizeof(uint32_t)) * (fs->block_size / sizeof(uint32_t));
	unsigned int min_trebly_block = min_doubly_block * (fs->block_size / sizeof(uint32_t));

	if(block < min_singly_block)
		return EXT2_TYPE_DIRECT_BLOCK;
	else if(block >= min_singly_block && block < min_doubly_block)
		return EXT2_TYPE_SINGLY_BLOCK;
	else if(block >= min_doubly_block && block < min_trebly_block)
		return EXT2_TYPE_DOUBLY_BLOCK;
	return EXT2_TYPE_TREBLY_BLOCK;
}
ssize_t ext2_read_inode_block(inode_t *ino, uint32_t blk, char *buffer, ext2_fs_t *fs)
{
	unsigned int type = ext2_detect_block_type(blk, fs);

	unsigned int min_singly_block = direct_block_count;
	unsigned int min_doubly_block = (fs->block_size / sizeof(uint32_t)) * (fs->block_size / sizeof(uint32_t));
	unsigned int min_trebly_block = min_doubly_block * (fs->block_size / sizeof(uint32_t));

	switch(type)
	{
		case EXT2_TYPE_DIRECT_BLOCK:
		{
			ext2_read_block_raw(ino->dbp[blk], 1, fs, buffer);
			break;
		}
		case EXT2_TYPE_SINGLY_BLOCK:
		{
			uint32_t *sbp = malloc(fs->block_size);
			if(!sbp)
				return errno = ENOMEM, -1;
			ext2_read_block_raw(ino->single_indirect_bp, 1, fs, sbp);
			ext2_read_block_raw(sbp[blk - min_singly_block], 1, fs, buffer);
			free(sbp);
			break;
		}
		case EXT2_TYPE_DOUBLY_BLOCK:
		{
			uint32_t *block = malloc(fs->block_size);
			if(!block)
				return errno = ENOMEM, -1;
			uint32_t block_index = blk;
			ext2_read_block_raw(ino->doubly_indirect_bp, 1, fs, block);
			ext2_read_block_raw(block[block_index - min_doubly_block], 1, fs, block);
			block_index -= min_doubly_block;
			ext2_read_block_raw(block[block_index - min_singly_block], 1, fs, buffer);

			free(block);
			break;
		}
		case EXT2_TYPE_TREBLY_BLOCK:
		{
			uint32_t *block = malloc(fs->block_size);
			if(!block)
				return errno = ENOMEM, -1;
			uint32_t block_index = blk - min_trebly_block;
			ext2_read_block_raw(ino->trebly_indirect_bp, 1, fs, block);
			ext2_read_block_raw(block[block_index], 1, fs, block);
			block_index -= min_doubly_block;
			ext2_read_block_raw(block[block_index], 1, fs, block);
			block_index -= min_doubly_block;
			ext2_read_block_raw(block[block_index - min_singly_block], 1, fs, buffer);

			free(block);
			break;
		}
	}
	return fs->block_size;
}
ssize_t ext2_get_block_from_inode(inode_t *ino, uint32_t block, ext2_fs_t *fs)
{
	unsigned int type = ext2_detect_block_type(block, fs);

	unsigned int min_singly_block = direct_block_count;
	unsigned int min_doubly_block = (fs->block_size / sizeof(uint32_t)) * (fs->block_size / sizeof(uint32_t));
	unsigned int min_trebly_block = min_doubly_block * (fs->block_size / sizeof(uint32_t));

	uint32_t ret = 0;
	switch(type)
	{
		case EXT2_TYPE_DIRECT_BLOCK:
		{
			ret = ino->dbp[block];
			break;
		}
		case EXT2_TYPE_SINGLY_BLOCK:
		{
			uint32_t *scratch = malloc(fs->block_size);
			if(!scratch)
				return errno = ENOMEM, -1;
			ext2_read_block_raw(ino->single_indirect_bp, 1, fs, scratch);
			ret = scratch[block - min_singly_block];
			free(scratch);
			break;
		}
		case EXT2_TYPE_DOUBLY_BLOCK:
		{
			uint32_t *scratch = malloc(fs->block_size);
			if(!scratch)
				return errno = ENOMEM, -1;
			uint32_t block_index = block;
			ext2_read_block_raw(ino->doubly_indirect_bp, 1, fs, scratch);
			ext2_read_block_raw(scratch[block_index - min_doubly_block], 1, fs, scratch);
			block_index -= min_doubly_block;
			ret = scratch[block_index - min_singly_block];
			free(scratch);
			break;
		}
		case EXT2_TYPE_TREBLY_BLOCK:
		{
			uint32_t *scratch = malloc(fs->block_size);
			if(!scratch)
				return errno = ENOMEM, -1;
			uint32_t block_index = block - min_trebly_block;
			ext2_read_block_raw(ino->trebly_indirect_bp, 1, fs, scratch);
			ext2_read_block_raw(scratch[block_index], 1, fs, scratch);
			block_index -= min_doubly_block;
			ext2_read_block_raw(scratch[block_index], 1, fs, scratch);
			block_index -= min_doubly_block;
			ret = scratch[block_index - min_singly_block];
			free(scratch);
			break;
		}
	}
	return ret;
}
uint32_t ext2_get_inode_block(inode_t *ino, uint32_t block, ext2_fs_t *fs)
{
	size_t total_size = EXT2_CALCULATE_SIZE64(ino);
	uint32_t max_blocks = total_size % fs->block_size ? (total_size / fs->block_size) + 1 : total_size / fs->block_size;
	if(max_blocks < block)
	{
		/* We'll have to allocate a new block and add it in */
		uint32_t new_block = ext2_allocate_block(fs);
		ext2_add_block_to_inode(ino, new_block, block, fs);
		return new_block;
	}
	else
		return ext2_get_block_from_inode(ino, block, fs);
	return -1;
}
ssize_t ext2_write_inode_block(inode_t *ino, uint32_t block, char *buffer, ext2_fs_t *fs)
{
	uint32_t blk = ext2_get_inode_block(ino, block, fs);
	if((int32_t) blk < 0)
		return -1;
	ext2_write_block(blk, 1, fs, buffer);
	return fs->block_size;
}
ssize_t ext2_write_inode(inode_t *ino, ext2_fs_t *fs, size_t size, off_t off, char *buffer)
{
	char *scratch = malloc(fs->block_size);
	if(!scratch)
		return errno = ENOMEM, -1;
	memset(scratch, 0, fs->block_size);
	ssize_t written = 0;
	while(written != (ssize_t) size)
	{
		uint32_t block = off / fs->block_size;
		off_t block_off = off % fs->block_size;
		off_t block_left = fs->block_size - block_off;
		ext2_read_inode_block(ino, block, scratch, fs);
		size_t amount = (ssize_t) size - written < block_left ? (ssize_t) size - written : block_left;
		memcpy(scratch + block_off, buffer + written, amount);
		ext2_write_inode_block(ino, block, scratch, fs);
		written += amount;
		off += amount;
	}
	free(scratch);
	return written;
}
/* Reads off an inode */
ssize_t ext2_read_inode(inode_t *ino, ext2_fs_t *fs, size_t size, off_t off, char *buffer)
{
	/* This scratch buffer is too big to be allocated on the stack */
	char *scratch = malloc(fs->block_size);
	if(!scratch)
		return errno = ENOMEM, -1;
	memset(scratch, 0, fs->block_size);
	ssize_t read = 0;
	while(read != (ssize_t) size)
	{
		uint32_t block = off / fs->block_size;
		off_t block_off = off % fs->block_size;
		off_t block_left = fs->block_size - block_off;
		ext2_read_inode_block(ino, block, scratch, fs);
		size_t amount = (ssize_t) (size - read) < block_left ? (ssize_t) size - read : block_left;
		memcpy(buffer + read, scratch + block_off, amount);
		read += amount;
		off += amount;
	}
	free(scratch);
	return read;
}
/* According to Linux and e2fs, this is how you detect fast symlinks */
inline _Bool ext2_is_fast_symlink(inode_t *inode, ext2_fs_t *fs)
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
	*symlink = strdup(path);
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
	return ino;
}
vfsnode_t *ext2_open(vfsnode_t *nd, const char *name)
{
	uint32_t inoden = nd->inode;
	ext2_fs_t *fs = fslist;
	uint32_t inode_num;
	size_t node_name_len;
	inode_t *ino;
	size_t size;
	char *inode_data;
	char *p;
	dir_entry_t *dir;
	char *saveptr;
	char *symlink_path;
	char *path;
	vfsnode_t *node;
	/* Get the inode structure from the number */
	ino = ext2_get_inode_from_number(fs, inoden);	
	/* Calculate the size of the directory */
	size = EXT2_CALCULATE_SIZE64(ino);
	p = strdup(name);
	if(!p)
		return errno = ENOMEM, NULL;
	inode_data = malloc(size);
	if(!inode_data)
	{
		free(p);
		return errno = ENOMEM, NULL;
	}
	ext2_read_inode(ino, fs, size, 0, inode_data);
	dir = (dir_entry_t*) inode_data;
	symlink_path = NULL;
	/* Get inodes by path segments */
	path = strtok_r(p, "/", &saveptr);
	while(path)
	{
		free(ino);
		ino = ext2_get_inode_from_dir(fs, dir, path, &inode_num);
		if(!ino)
			return errno = ENOENT, NULL;
		if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_SYMLINK)
		{
			uint32_t num;
			inode_t *parent_dir = ext2_get_inode_from_dir(fs, dir, ".", &num);
			ino = ext2_follow_symlink(ino, fs, parent_dir, &inode_num, &symlink_path);
			if(!ino)
				return errno = ENOMEM, NULL;
			free(parent_dir);
		}
		inode_data = realloc(inode_data, EXT2_CALCULATE_SIZE64(ino));
		if(!inode_data)
			return errno = ENOMEM, NULL;
		ext2_read_inode(ino, fs, size, 0, inode_data);
		dir = (dir_entry_t*)inode_data;
		/* Get the next path segment */
		path = strtok_r(NULL, "/", &saveptr);
		/* The symlink path is useless if it's not the last token */
		if(path)
		{
			free(symlink_path);
			symlink_path = NULL;
		}
	}
	node = malloc(sizeof(vfsnode_t));
	if(!node)
	{
		free(ino);
		return errno = ENOMEM, NULL;
	}
	memset(node, 0, sizeof(vfsnode_t));
	if(symlink_path)
		node_name_len = strlen(nd->name) + 1 + strlen(symlink_path) + 1;
	else
		node_name_len = strlen(nd->name) + 1 + strlen(name) + 1;
	node->name = malloc(node_name_len);
	if(!node->name)
	{
		free(node);
		free(ino);
		free(p);
		return errno = ENOMEM, NULL;
	}
	memset(node->name, 0, node_name_len);
	strcpy(node->name, nd->name);
	strcat(node->name, "/");
	strcat(node->name, symlink_path != NULL ? symlink_path : name);
	node->dev = nd->dev;
	node->inode = inode_num;
	/* Detect the file type */
	if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_DIR)
		node->type = VFS_TYPE_DIR;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_REGFILE)
		node->type = VFS_TYPE_FILE;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_BLOCKDEV)
		node->type = VFS_TYPE_BLOCK_DEVICE;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_CHARDEV)
		node->type = VFS_TYPE_CHAR_DEVICE;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_SYMLINK)
		node->type = VFS_TYPE_SYMLINK;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_FIFO)
		node->type = VFS_TYPE_FIFO;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_UNIX_SOCK)
		node->type = VFS_TYPE_UNIX_SOCK;
	else
		node->type = VFS_TYPE_UNK;
	node->size = EXT2_CALCULATE_SIZE64(ino);
	node->uid = ino->uid;
	node->gid = ino->gid;
	
	free(ino);
	return node;
}
vfsnode_t *ext2_creat(const char *path, int mode, vfsnode_t *file)
{
	/* Create a file */
	return NULL;
}
vfsnode_t *ext2_mount_partition(uint64_t sector, block_device_t *dev)
{
	LOG("ext2", "mounting ext2 partition at sector %d\n", sector);
	superblock_t *sb = malloc(sizeof(superblock_t));
	if(!sb)
		return errno = ENOMEM, NULL;
	blkdev_read((sector + 2) * 512, 1024, sb, dev);
	if(sb->ext2sig == 0xef53)
		LOG("ext2", "valid ext2 signature detected!\n");
	else
	{
		ERROR("ext2", "invalid ext2 signature %x\n", sb->ext2sig);
		return errno = EINVAL, NULL;
	}
	ext2_fs_t *fs = malloc(sizeof(ext2_fs_t));
	if(!fs)
	{
		free(sb);
		return errno = ENOMEM, NULL;
	}
	memset(fs, 0, sizeof(ext2_fs_t));
	if(!fslist) fslist = fs;
	else
	{
		ext2_fs_t *s = fslist;
		while(s->next)
		{
			s = s->next;
		}
		s->next = fs;
	}

	fs->sb = sb;
	fs->major = sb->major_version;
	fs->minor = sb->minor_version;
	fs->first_sector = sector;
	fs->total_inodes = sb->total_inodes;
	fs->total_blocks = sb->total_blocks;
	fs->block_size = 1024 << sb->log2blocksz;
	fs->frag_size = 1024 << sb->log2fragsz;
	fs->inode_size = sb->size_inode_bytes;
	fs->blkdevice = dev;
	fs->blocks_per_block_group = sb->blockgroupblocks;
	fs->inodes_per_block_group = sb->blockgroupinodes;
	fs->number_of_block_groups = fs->total_blocks / fs->blocks_per_block_group;
	if (fs->total_blocks % fs->blocks_per_block_group)
		fs->number_of_block_groups++;
	block_group_desc_t *bgdt = NULL;
	size_t blocks_for_bgdt = (fs->number_of_block_groups * sizeof(block_group_desc_t)) / fs->block_size;
	if((fs->number_of_block_groups * sizeof(block_group_desc_t)) % fs->block_size)
		blocks_for_bgdt++;
	if(fs->block_size == 1024)
		bgdt = ext2_read_block(2, (uint16_t)blocks_for_bgdt, fs);
	else
		bgdt = ext2_read_block(1, (uint16_t)blocks_for_bgdt, fs);
	fs->bgdt = bgdt;
	vfsnode_t *node = malloc(sizeof(vfsnode_t));
	if(!node)
	{
		free(sb);
		return errno = ENOMEM, NULL;
	}
	node->name = "";
	node->inode = 2;
	node->type = VFS_TYPE_DIR;
	struct minor_device *minor = dev_register(MAJOR(dev->dev), 0);
	if(!minor)
	{
		free(node);
		return NULL;
	}
	minor->fops = malloc(sizeof(struct file_ops));
	if(!minor->fops)
	{
		free(node);
		free(minor);
		return errno = ENOMEM, NULL;
	}
	memset(minor->fops, 0, sizeof(struct file_ops));
	minor->fops->open = ext2_open;
	minor->fops->read = ext2_read;
	minor->fops->write = ext2_write;
	minor->fops->getdents = ext2_getdents;
	minor->fops->stat = ext2_stat;

	node->dev = minor->majorminor;
	return node;
}
__init void init_ext2drv()
{
	if(partition_add_handler(ext2_mount_partition, "ext2", EXT2_MBR_CODE, ext2_gpt_uuid, 4) == 1)
		FATAL("ext2", "error initializing the handler data\n");
}
unsigned int ext2_getdents(unsigned int count, struct dirent* dirp, off_t off, vfsnode_t* this)
{
	size_t read = 0;
	uint32_t inoden = this->inode;
	ext2_fs_t *fs = fslist;
	/* Get the inode structure */
	inode_t *ino = ext2_get_inode_from_number(fs, inoden);	

	size_t inode_size = EXT2_CALCULATE_SIZE64(ino); 
	dir_entry_t *dir_entries = malloc(inode_size);
	if(!dir_entries)
	{
		free(ino);
		return errno = ENOMEM, (unsigned int) -1;
	}
	if(ext2_read_inode(ino, fs, inode_size, 0, (char*) dir_entries) != (ssize_t) inode_size)
	{
		free(ino);
		free(dir_entries);
		return (unsigned int) -1;
	}
	while(read < count)
	{
		if(dir_entries->inode == 0 && (ssize_t) read == off)
			return 0;
		if(dir_entries->inode == 0)
			return read;
		if(read + dir_entries->lsbit_namelen + 1 + sizeof(ino_t) + sizeof(off_t) + sizeof(unsigned short) + sizeof(unsigned char) > count)
			return read;
		dirp->d_ino = dir_entries->inode;
		/* Set the dirent type */
		switch(dir_entries->type_indic)
		{
			case 1:
				dirp->d_type = DT_REG;
				break;
			case 4:
				dirp->d_type = DT_BLK;
				break;
			case 2:
				dirp->d_type = DT_DIR;
				break;
			case 3:
				dirp->d_type = DT_CHR;
				break;
			case 5:
				dirp->d_type = DT_FIFO;
				break;
			case 7:
				dirp->d_type = DT_LNK;
				break;
			case 6:
				dirp->d_type = DT_SOCK;
				break;
			default:
				dirp->d_type = DT_UNKNOWN;
				break;
		}
		memcpy(dirp->d_name, dir_entries->name, dir_entries->lsbit_namelen);
		dirp->d_name[strlen(dirp->d_name)] = '\0';
		dirp->d_reclen = dir_entries->lsbit_namelen + 1 + sizeof(ino_t) + sizeof(off_t) + sizeof(unsigned short) + sizeof(unsigned char);
		read += dirp->d_reclen;
		dirp = (struct dirent *)((char*) dirp + dirp->d_reclen);
		dir_entries = (dir_entry_t*)((char*)dir_entries + dir_entries->size);
	}
	return read;
}
int ext2_stat(struct stat *buf, vfsnode_t *node)
{
	uint32_t inoden = node->inode;
	ext2_fs_t *fs = fslist;
	/* Get the inode structure */
	inode_t *ino = ext2_get_inode_from_number(fs, inoden);	

	if(!ino)
		return 1;
	/* Start filling the structure */
	buf->st_dev = node->dev;
	buf->st_ino = node->inode;
	buf->st_nlink = ino->hard_links;
	buf->st_mode = ino->mode;
	buf->st_uid = node->uid;
	buf->st_gid = node->gid;
	buf->st_size = EXT2_CALCULATE_SIZE64(ino);
	buf->st_atime = ino->atime;
	buf->st_mtime = ino->mtime;
	buf->st_ctime = ino->ctime;
	buf->st_blksize = fs->block_size;
	buf->st_blocks = buf->st_size % fs->block_size ? (buf->st_size / fs->block_size) + 1 : buf->st_size / fs->block_size;
	
	return 0;
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
