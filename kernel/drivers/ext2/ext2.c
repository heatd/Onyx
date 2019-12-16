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
#include <string.h>

#include <sys/types.h>

#include <onyx/vm.h>
#include <onyx/vfs.h>
#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/log.h>

#include "../include/ext2.h"

struct inode *ext2_open(struct inode *nd, const char *name);
size_t ext2_read(int flags, size_t offset, size_t sizeofreading, void *buffer, struct inode *node);
size_t ext2_write(size_t offset, size_t sizeofwrite, void *buffer, struct inode *node);
off_t ext2_getdirent(struct dirent *buf, off_t off, struct inode* this);
int ext2_stat(struct stat *buf, struct inode *node);
struct inode *ext2_creat(const char *path, int mode, struct inode *file);

struct file_ops ext2_ops = 
{
	.open = ext2_open,
	.read = ext2_read,
	.write = ext2_write,
	.getdirent = ext2_getdirent,
	.stat = ext2_stat,
	.creat = ext2_creat
};

uuid_t ext2_gpt_uuid[4] = 
{
	{0x3DAF, 0x0FC6, 0x8483, 0x4772, 0x798E, 0x693D, 0x47D8, 0xE47D}, /* Linux filesystem data */
	/* I'm not sure that the following entries are used, and they're probably broken */
	{0xBCE3, 0x4F68, 0x4DB1, 0xE8CD, 0xFBCA, 0x96E7, 0xB709, 0xF984}, /* Root partition (x86-64) */
	{0xC7E1, 0x933A, 0x4F13, 0x2EB4, 0x0E14, 0xB844, 0xF915, 0xE2AE}, /* /home partition */
	{0x8425, 0x3B8F, 0x4F3B, 0x20E0, 0x1A25, 0x907F, 0x98E8, 0xA76F} /* /srv (server data) partition */
};

ext2_fs_t *fslist = NULL;

inode_t *ext2_get_inode_from_dir(ext2_fs_t *fs, dir_entry_t *dirent, char *name, uint32_t *inode_number,
	size_t size)
{
	dir_entry_t *dirs = dirent;
	while((uintptr_t) dirs < (uintptr_t) dirent + size)
	{
		if(dirs->lsbit_namelen == strlen(name) && 
		   !memcmp(dirs->name, name, dirs->lsbit_namelen))
		{
			*inode_number = dirs->inode;
			return ext2_get_inode_from_number(fs, dirs->inode);
		}
		dirs = (dir_entry_t*)((char*) dirs + dirs->size);
	}
	return NULL;
}

size_t ext2_write(size_t offset, size_t sizeofwrite, void *buffer, struct inode *node)
{
	ext2_fs_t *fs = node->i_sb->s_helper;
	inode_t *ino = ext2_get_inode_from_number(fs, node->i_inode);
	if(!ino)
		return errno = EINVAL, (size_t) -1;

	size_t size = ext2_write_inode(ino, fs, sizeofwrite, offset, buffer);

	if(offset + size > EXT2_CALCULATE_SIZE64(ino))
	{
		ext2_set_inode_size(ino, offset + size);
		node->i_size = offset + size;
	}

	ext2_update_inode(ino, fs, node->i_inode);

	free(ino);
	return size;
}

size_t ext2_read(int flags, size_t offset, size_t sizeofreading, void *buffer, struct inode *node)
{
	//printk("Inode read: %lu, off %lu, size %lu\n", node->i_inode, offset, sizeofreading);
	ext2_fs_t *fs = node->i_sb->s_helper;

	inode_t *ino = ext2_get_inode_from_number(fs, node->i_inode);
	if(!ino)
		return errno = EINVAL, -1;

	/* We don't use the flags for now, only for things that might block */
	(void) flags;
	if(node->i_type == VFS_TYPE_DIR)
	{
		node->i_size = EXT2_CALCULATE_SIZE64(ino);
	}

	if(offset > node->i_size)
		return errno = EINVAL, -1;

	size_t to_be_read = offset + sizeofreading > node->i_size ?
		node->i_size - offset : sizeofreading;

	size_t size = ext2_read_inode(ino, fs, to_be_read, offset, buffer);

	free(ino);
	return size;
}

struct inode *ext2_open(struct inode *nd, const char *name)
{
	uint32_t inoden = nd->i_inode;
	ext2_fs_t *fs = nd->i_sb->s_helper;
	uint32_t inode_num;
	inode_t *ino;
	char *symlink_path = NULL;
	struct inode *node = NULL;
	/* Get the inode structure from the number */
	ino = ext2_get_inode_from_number(fs, inoden);	
	if(!ino)
		return NULL;
	ino = ext2_traverse_fs(ino, name, fs, &symlink_path, &inode_num);
	if(!ino)
		return NULL;

	/* See if we have the inode cached in the 	 */
	node = superblock_find_inode(nd->i_sb, inode_num);
	if(node)
		return node;

	node = inode_create();
	if(!node)
	{
		free(ino);
		return errno = ENOMEM, NULL;
	}

	node->i_dev = nd->i_dev;
	node->i_inode = inode_num;
	/* Detect the file type */
	if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_DIR)
		node->i_type = VFS_TYPE_DIR;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_REGFILE)
		node->i_type = VFS_TYPE_FILE;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_BLOCKDEV)
		node->i_type = VFS_TYPE_BLOCK_DEVICE;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_CHARDEV)
		node->i_type = VFS_TYPE_CHAR_DEVICE;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_SYMLINK)
		node->i_type = VFS_TYPE_SYMLINK;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_FIFO)
		node->i_type = VFS_TYPE_FIFO;
	else if(EXT2_GET_FILE_TYPE(ino->mode) == EXT2_INO_TYPE_UNIX_SOCK)
		node->i_type = VFS_TYPE_UNIX_SOCK;
	else
		node->i_type = VFS_TYPE_UNK;

	node->i_size = EXT2_CALCULATE_SIZE64(ino);
	node->i_uid = ino->uid;
	node->i_gid = ino->gid;
	node->i_sb = nd->i_sb;

	memcpy(&node->i_fops, &ext2_ops, sizeof(struct file_ops));
	free(ino);

	/* Cache the inode */
	superblock_add_inode(nd->i_sb, node);

	return node;
}

time_t get_posix_time(void);

struct inode *ext2_creat(const char *name, int mode, struct inode *file)
{
	ext2_fs_t *fs = file->i_sb->s_helper;
	uint32_t inumber = 0;

	inode_t *inode = ext2_allocate_inode(&inumber, fs);
	inode_t *dir_inode = ext2_get_inode_from_number(fs, file->i_inode);
	if(!dir_inode)
		return NULL;
	if(!inode)
	{
		free(dir_inode);
		return NULL;
	}

	memset(inode, 0, sizeof(inode_t));
	inode->ctime = inode->atime = inode->mtime = (uint32_t) get_posix_time();
	inode->hard_links = 1;
	inode->mode = EXT2_INO_TYPE_REGFILE | mode;

	ext2_update_inode(inode, fs, inumber);
	ext2_update_inode(dir_inode, fs, file->i_inode);
	
	if(ext2_add_direntry(name, inumber, inode, dir_inode, fs) < 0)
	{
		free(inode);
		free(dir_inode);
		ext2_free_inode(inumber, fs);
		return NULL;
	}

	/* Create a file */
	struct inode *ino = inode_create();

	if(!ino)
	{
		/* TODO: Remove the direntry from the directory */
		free(inode);
		free(dir_inode);
		ext2_free_inode(inumber, fs);
		return NULL;
	}

	ino->i_dev = file->i_dev;
	ino->i_inode = inumber;
	/* Detect the file type */
	if(EXT2_GET_FILE_TYPE(inode->mode) == EXT2_INO_TYPE_DIR)
		ino->i_type = VFS_TYPE_DIR;
	else if(EXT2_GET_FILE_TYPE(inode->mode) == EXT2_INO_TYPE_REGFILE)
		ino->i_type = VFS_TYPE_FILE;
	else if(EXT2_GET_FILE_TYPE(inode->mode) == EXT2_INO_TYPE_BLOCKDEV)
		ino->i_type = VFS_TYPE_BLOCK_DEVICE;
	else if(EXT2_GET_FILE_TYPE(inode->mode) == EXT2_INO_TYPE_CHARDEV)
		ino->i_type = VFS_TYPE_CHAR_DEVICE;
	else if(EXT2_GET_FILE_TYPE(inode->mode) == EXT2_INO_TYPE_SYMLINK)
		ino->i_type = VFS_TYPE_SYMLINK;
	else if(EXT2_GET_FILE_TYPE(inode->mode) == EXT2_INO_TYPE_FIFO)
		ino->i_type = VFS_TYPE_FIFO;
	else if(EXT2_GET_FILE_TYPE(inode->mode) == EXT2_INO_TYPE_UNIX_SOCK)
		ino->i_type = VFS_TYPE_UNIX_SOCK;
	else
		ino->i_type = VFS_TYPE_UNK;

	ino->i_size = EXT2_CALCULATE_SIZE64(inode);
	ino->i_uid = inode->uid;
	ino->i_gid = inode->gid;
	ino->i_sb = file->i_sb;

	memcpy(&ino->i_fops, &ext2_ops, sizeof(struct file_ops));
	
	superblock_add_inode(ino->i_sb, ino);

	free(inode);
	free(dir_inode);

	return ino;
}

__attribute__((no_sanitize_undefined))
struct inode *ext2_mount_partition(uint64_t sector, block_device_t *dev)
{
	LOG("ext2", "mounting ext2 partition at sector %lu\n", sector);
	superblock_t *sb = malloc(sizeof(superblock_t));
	if(!sb)
		return NULL;
	blkdev_read((sector + 2) * 512, 1024, sb, dev);
	if(sb->ext2sig == 0xef53)
		LOG("ext2", "valid ext2 signature detected!\n");
	else
	{
		ERROR("ext2", "invalid ext2 signature %x\n", sb->ext2sig);
		free(sb);
		return errno = EINVAL, NULL;
	}

	ext2_fs_t *fs = zalloc(sizeof(*fs));
	if(!fs)
	{
		free(sb);
		return NULL;
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
	unsigned long entries = fs->block_size / sizeof(uint32_t);
	fs->entry_shift = 31 - __builtin_clz(entries);

	if (fs->total_blocks % fs->blocks_per_block_group)
		fs->number_of_block_groups++;
	/* The driver keeps a block sized zero'd mem chunk for easy and fast overwriting of blocks */
	fs->zero_block = zalloc(fs->block_size);
	if(!fs->zero_block)
	{
		free(sb);
		free(fs);
		return errno = ENOMEM, NULL;
	}

	block_group_desc_t *bgdt = NULL;
	size_t blocks_for_bgdt = (fs->number_of_block_groups *
		sizeof(block_group_desc_t)) / fs->block_size;

	if((fs->number_of_block_groups * sizeof(block_group_desc_t)) % fs->block_size)
		blocks_for_bgdt++;
	if(fs->block_size == 1024)
		bgdt = ext2_read_block(2, (uint16_t) blocks_for_bgdt, fs);
	else
		bgdt = ext2_read_block(1, (uint16_t) blocks_for_bgdt, fs);
	fs->bgdt = bgdt;

	struct superblock *new_super = zalloc(sizeof(*new_super));
	if(!sb)
	{
		free(sb);
		free(fs->zero_block);
		free(fs);
		return NULL;
	}

	struct inode *node = inode_create();
	if(!node)
	{
		free(sb);
		free(new_super);
		free(fs->zero_block);
		free(fs);
		return errno = ENOMEM, NULL;
	}

	node->i_inode = 2;
	node->i_type = VFS_TYPE_DIR;
	node->i_sb = new_super;

	new_super->s_inodes = node;
	new_super->s_helper = fs;

	memcpy(&node->i_fops, &ext2_ops, sizeof(struct file_ops));
	return node;
}

__init void init_ext2drv()
{
	if(partition_add_handler(ext2_mount_partition, "ext2", EXT2_MBR_CODE,
		ext2_gpt_uuid, 4) == 1)
		FATAL("ext2", "error initializing the handler data\n");
}

off_t ext2_getdirent(struct dirent *buf, off_t off, struct inode* this)
{
	off_t new_off;
	dir_entry_t entry;
	size_t read;

	/* Read a dir entry from the offset */
	read = ext2_read(0, off, sizeof(dir_entry_t), &entry, this);

	/* If we reached the end of the directory buffer, return 0 */
	if(read == 0)
		return 0;

	/* If we reached the end of the directory list, return 0 */
	if(!entry.inode && !entry.lsbit_namelen)
		return 0;

	memcpy(buf->d_name, entry.name, entry.lsbit_namelen);
	buf->d_name[entry.lsbit_namelen] = '\0';
	buf->d_ino = entry.inode;
	buf->d_off = off;
	buf->d_reclen = sizeof(struct dirent) - (256 - (entry.lsbit_namelen + 1));
	buf->d_type = entry.type_indic;

	new_off = off + entry.size;

	return new_off;
}

int ext2_stat(struct stat *buf, struct inode *node)
{
	uint32_t inoden = node->i_inode;
	ext2_fs_t *fs = node->i_sb->s_helper;
	/* Get the inode structure */
	inode_t *ino = ext2_get_inode_from_number(fs, inoden);	

	if(!ino)
		return 1;
	/* Start filling the structure */
	buf->st_dev = node->i_dev;
	buf->st_ino = node->i_inode;
	buf->st_nlink = ino->hard_links;
	buf->st_mode = ino->mode;
	buf->st_uid = node->i_uid;
	buf->st_gid = node->i_gid;
	buf->st_size = EXT2_CALCULATE_SIZE64(ino);
	buf->st_atime = ino->atime;
	buf->st_mtime = ino->mtime;
	buf->st_ctime = ino->ctime;
	buf->st_blksize = fs->block_size;
	buf->st_blocks = ino->i_blocks;
	
	return 0;
}
