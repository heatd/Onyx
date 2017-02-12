/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <mbr.h>
#include <partitions.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>

#include <kernel/vmm.h>
#include <kernel/vfs.h>
#include <kernel/compiler.h>
#include <kernel/dev.h>
#include <kernel/log.h>

#include <drivers/rtc.h>
#include <drivers/ext2.h>

#define EXT2_TYPE_DIRECT_BLOCK		0
#define EXT2_TYPE_SINGLY_BLOCK		1
#define EXT2_TYPE_DOUBLY_BLOCK		2
#define EXT2_TYPE_TREBLY_BLOCK		3
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
void *ext2_read_block(uint32_t block_index, uint16_t blocks, ext2_fs_t *fs)
{
	size_t size = blocks * fs->block_size; /* size = nblocks * block size */
	void *buff = malloc(size); /* Allocate a buffer */
	if(!buff)
		return NULL;
	memset(buff, 0, size);
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
	/* Update atime */
	inode_block->atime = (uint32_t) get_posix_time();
	ext2_write_block(bgd->inode_table_addr + block, 1, fs, inode_table);

	return inode_block;
}
inode_t *ext2_get_inode_from_dir(ext2_fs_t *fs, dir_entry_t *dirent, char *name, uint32_t *inode_number)
{
	dir_entry_t *dirs = dirent;
	while(dirs->inode != 0)
	{
		printk("dirs %s\n", dirs->name);
		if(!strcmp(dirs->name, name))
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
	uint32_t block_index = offset / fs->block_size;
	if(offset % fs->block_size)
		block_index--;
	inode_t *ino = ext2_get_inode_from_number(fs, node->inode);
	if(!ino)
		return errno = EINVAL, (size_t) -1;
	/* Ok, this one will be tricky. I'll need to handle 3 different cases of writing. 
	 * 1 - Overwriting file data - this one is easy. Just get the block offset and write to it, then write to disk again again
	 * 2 - We're writing to a block that's already allocated to the inode, and zeroed - this is also easy, just write to it
	 * 3 - We're writing to a new block - this one is the hardest. We'll need to allocate a new block, and add it to the disk inode
	 * this one will require many more writes and reads than usual.
	*/
	/*if(offset < node->size)
	{
		// This is case 1 of ext2_write
		char *buf = malloc(sizeofwrite);
		if(!buf)
			return errno = ENOMEM, -1;
		printf("Block index: %u\nSize of write: %u\n", block_index, sizeofwrite);
		size_t read = ext2_read_file(ino, fs, sizeofwrite, block_index, buf);
		if(read == (size_t)-1)
			return errno = EIO, -1;
		memcpy(buf + (offset % fs->block_size), buffer, sizeofwrite);
		printf("Writing!\n");
		return ext2_write_file(ino, fs, sizeofwrite, block_index, buf);
	}*/
	return errno = ENOSYS, -1;
}
size_t ext2_read(size_t offset, size_t sizeofreading, void *buffer, vfsnode_t *nd)
{
	if(offset > nd->size)
		return errno = EINVAL, -1;
	ext2_fs_t *fs = fslist;
	uint32_t block_index = offset / fs->block_size;
	if(offset % fs->block_size)
		block_index++;
	inode_t *ino = ext2_get_inode_from_number(fs, nd->inode);
	if(!ino)
		return errno = EINVAL;
	size_t size = ext2_read_inode(ino, fs, sizeofreading, block_index, buffer);
	return size;
}
unsigned int ext2_detect_block_type(uint32_t block, ext2_fs_t *fs)
{
	unsigned int min_singly_block = direct_block_count + 1;
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
inline ssize_t ext2_read_inode_block(inode_t *ino, uint32_t block, char *buffer, ext2_fs_t *fs)
{
	unsigned int type = ext2_detect_block_type(block, fs);
	
	unsigned int min_singly_block = direct_block_count + 1;
	unsigned int min_doubly_block = (fs->block_size / sizeof(uint32_t)) * (fs->block_size / sizeof(uint32_t));
	unsigned int min_trebly_block = min_doubly_block * (fs->block_size / sizeof(uint32_t));

	switch(type)
	{
		case EXT2_TYPE_DIRECT_BLOCK:
		{
			ext2_read_block_raw(block, 1, fs, buffer);
			break;
		}
		case EXT2_TYPE_SINGLY_BLOCK:
		{
			char *sbp = malloc(fs->block_size);
			if(!sbp)
				return errno = ENOMEM, -1;
			ext2_read_block_raw(ino->single_indirect_bp, 1, fs, sbp);
			ext2_read_block_raw(sbp[block - min_singly_block], 1, fs, buffer);
			free(sbp);
			break;
		}
		case EXT2_TYPE_DOUBLY_BLOCK:
		{
			char *sbp = malloc(fs->block_size);
			if(!sbp)
				return errno = ENOMEM, -1;
			char *dbp = malloc(fs->block_size);
			if(!dbp)
			{
				free(sbp);
				return errno = ENOMEM, -1;
			}
			uint32_t block_index = block;
			ext2_read_block_raw(ino->doubly_indirect_bp, 1, fs, dbp);
			ext2_read_block_raw(dbp[block_index - min_doubly_block], 1, fs, sbp);
			block_index -= min_doubly_block;
			free(sbp);
			ext2_read_block_raw(sbp[block_index - min_singly_block], 1, fs, buffer);

			free(dbp);
			break;
		}
		case EXT2_TYPE_TREBLY_BLOCK:
		{
			char *sbp = malloc(fs->block_size);
			if(!sbp)
				return errno = ENOMEM, -1;
			char *dbp = malloc(fs->block_size);
			if(!dbp)
			{
				free(sbp);
				return errno = ENOMEM, -1;
			}
			char *tbp = malloc(fs->block_size);
			if(!tbp)
			{
				free(dbp);
				free(sbp);
				return errno = ENOMEM, -1;
			}
			uint32_t block_index = block - min_trebly_block;
			ext2_read_block_raw(ino->trebly_indirect_bp, 1, fs, tbp);
			ext2_read_block_raw(tbp[block_index], 1, fs, dbp);
			block_index -= min_doubly_block;
			ext2_read_block_raw(dbp[block_index], 1, fs, sbp);
			block_index -= min_doubly_block;
			ext2_read_block_raw(sbp[block_index - min_singly_block], 1, fs, buffer);

			free(tbp);
			free(sbp);
			free(dbp);
			break;
		}
	}
	return fs->block_size;
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
		size_t amount = (ssize_t) size - read < block_left ? (ssize_t) size - read : block_left;
		memcpy(buffer + read, scratch + block_off, amount);
		read += amount;
		off += amount;
	}
	free(scratch);
	return read;
}
vfsnode_t *ext2_open(vfsnode_t *nd, const char *name)
{
	uint32_t inoden = nd->inode;
	ext2_fs_t *fs = fslist;
	uint32_t inode_num;
	/* Get the inode structure from the number */
	inode_t *ino = ext2_get_inode_from_number(fs, inoden);	
	/* Calculate the size of the directory */
	size_t size = ((uint64_t)ino->size_hi << 32) | ino->size_lo;
	char *p = strdup(name);
	char *inode_data = malloc(size);
	if(!inode_data)
		return errno = ENOMEM, NULL;

	ext2_read_inode(ino, fs, size, 0, inode_data);
	dir_entry_t *dir = (dir_entry_t*)inode_data;
	while(p)
	{
		if(p != name)
			p++;
		// Count the size needed to contain the name
		size_t len = 0;
		while(p[len] != '\0' && p[len] != '/')
		{
			len++;
		}
		char *path = malloc(len+2);
		if(!path)
			return errno = ENOMEM, NULL;
		memset(path, 0, len); // This memset is just to make sure the string is zero-terminated
		memcpy(path, p, len);
		ino = ext2_get_inode_from_dir(fs, dir, path, &inode_num);
		if(!ino)
			return errno = ENOENT, NULL;
		if(strtok(p, "/") == NULL)
			break;
		inode_data = malloc(size);
		if(!inode_data)
			return errno = ENOMEM, NULL;
		ext2_read_inode(ino, fs, size, 0, inode_data);
		dir = (dir_entry_t*)inode_data;
		p = strtok(p, "/");
		free(path);
	}
	vfsnode_t *node = malloc(sizeof(vfsnode_t));
	if(!node)
	{
		free(ino);
		return errno = ENOMEM, NULL;
	}
	memset(node, 0, sizeof(vfsnode_t));
	node->name = (char*) name;
	node->dev = nd->dev;
	node->inode = inode_num;
	node->size = ((uint64_t)ino->size_hi << 32) | ino->size_lo;
	node->uid = ino->uid;
	node->gid = ino->gid;
	return node;
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
	printk("Blocks for bgdt: %u\n", blocks_for_bgdt);
	vfsnode_t *node = malloc(sizeof(vfsnode_t));
	if(!node)
	{
		free(sb);
		return errno = ENOMEM, NULL;
	}
	node->name = "";
	node->inode = 2;
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

	node->dev = minor->majorminor;
	open_vfs(node, "Hello\n");
	while(1);
	printk("errno: %u\n", errno);
	return node;
}
__init void init_ext2drv()
{
	if(partition_add_handler(ext2_mount_partition, "ext2", EXT2_MBR_CODE, ext2_gpt_uuid, 4) == 1)
		FATAL("ext2", "error initializing the handler data\n");
}
