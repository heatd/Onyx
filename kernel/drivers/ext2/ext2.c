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

uuid_t ext2_gpt_uuid[4] = 
{
	{0x3DAF, 0x0FC6, 0x8483, 0x4772, 0x798E, 0x693D, 0x47D8, 0xE47D}, /* Linux filesystem data */
	/* I'm not sure that the following entries are used, and they're probably broken */
	{0xBCE3, 0x4F68, 0x4DB1, 0xE8CD, 0xFBCA, 0x96E7, 0xB709, 0xF984}, /* Root partition (x86-64) */
	{0xC7E1, 0x933A, 0x4F13, 0x2EB4, 0x0E14, 0xB844, 0xF915, 0xE2AE}, /* /home partition */
	{0x8425, 0x3B8F, 0x4F3B, 0x20E0, 0x1A25, 0x907F, 0x98E8, 0xA76F} /* /srv (server data) partition */
};
ext2_fs_t *fslist = NULL;
int ext2_stat(struct stat *buf, vfsnode_t *node);
unsigned int ext2_getdents(unsigned int count, struct dirent* dirp, off_t off, vfsnode_t* this);

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
	printk("Writing to off %u, size %u, name %s\n", offset, sizeofwrite, node->name);
	ext2_fs_t *fs = fslist;
	inode_t *ino = ext2_get_inode_from_number(fs, node->inode);
	if(!ino)
		return errno = EINVAL, (size_t) -1;
	size_t size = ext2_write_inode(ino, fs, sizeofwrite, offset, buffer);
	if(offset + size > EXT2_CALCULATE_SIZE64(ino))
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
vfsnode_t *ext2_open(vfsnode_t *nd, const char *name)
{
	uint32_t inoden = nd->inode;
	ext2_fs_t *fs = fslist;
	uint32_t inode_num;
	size_t node_name_len;
	inode_t *ino;
	char *symlink_path = NULL;
	vfsnode_t *node;
	/* Get the inode structure from the number */
	ino = ext2_get_inode_from_number(fs, inoden);	
	if(!ino)
		return NULL;
	ino = ext2_traverse_fs(ino, name, fs, &symlink_path, &inode_num);
	if(!ino)
		return NULL;
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
		free(sb);
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
	/* The driver keeps a block sized zero'd mem chunk for easy and fast overwriting of blocks */
	fs->zero_block = malloc(fs->block_size);
	if(!fs->zero_block)
	{
		free(sb);
		return errno = ENOMEM, NULL;
	}
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
	buf->st_blocks = ino->i_blocks;
	
	return 0;
}
