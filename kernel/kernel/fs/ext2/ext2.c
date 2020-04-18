/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#define _POSIX_SOURCE
#include <limits.h>
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
#include <onyx/panic.h>
#include <onyx/cred.h>

#include "ext2.h"

struct inode *ext2_open(struct file *nd, const char *name);
size_t ext2_read(size_t offset, size_t sizeofreading, void *buffer, struct file *node);
size_t ext2_write(size_t offset, size_t sizeofwrite, void *buffer, struct file *node);
off_t ext2_getdirent(struct dirent *buf, off_t off, struct file* this);
int ext2_stat(struct stat *buf, struct file *node);
struct inode *ext2_creat(const char *path, int mode, struct file *file);
char *ext2_readlink(struct file *ino);
void ext2_close(struct inode *ino);
struct inode *ext2_mknod(const char *name, mode_t mode, dev_t dev, struct file *ino);
struct inode *ext2_mkdir(const char *name, mode_t mode, struct file *ino);
int ext2_link_fops(struct file *target, const char *name, struct file *dir);
int ext2_unlink(const char *name, int flags, struct file *f);
int ext2_fallocate(int mode, off_t off, off_t len, struct file *f);
int ext2_ftruncate(off_t off, struct file *f);
ssize_t ext2_readpage(struct page *page, size_t off, struct inode *ino);
ssize_t ext2_writepage(struct page *page, size_t off, struct inode *ino);

int ext2_link(struct inode *target, const char *name, struct inode *dir);

struct file_ops ext2_ops = 
{
	.open = ext2_open,
	.read = ext2_read,
	.write = ext2_write,
	.getdirent = ext2_getdirent,
	.stat = ext2_stat,
	.creat = ext2_creat,
	.readlink = ext2_readlink,
	.close = ext2_close,
	.mknod = ext2_mknod,
	.mkdir = ext2_mkdir,
	.link = ext2_link_fops,
	.unlink = ext2_unlink,
	.fallocate = ext2_fallocate,
	.ftruncate = ext2_ftruncate,
	.readpage = ext2_readpage,
	.writepage = ext2_writepage
};

struct ext2_inode *ext2_get_inode_from_dir(ext2_fs_t *fs, dir_entry_t *dirent, char *name, uint32_t *inode_number,
	size_t size)
{
	dir_entry_t *dirs = dirent;
	while((uintptr_t) dirs < (uintptr_t) dirent + size)
	{
		if(dirs->inode && dirs->lsbit_namelen == strlen(name) && 
		   !memcmp(dirs->name, name, dirs->lsbit_namelen))
		{
			*inode_number = dirs->inode;
			return ext2_get_inode_from_number(fs, dirs->inode);
		}
		dirs = (dir_entry_t*)((char*) dirs + dirs->size);
	}
	return NULL;
}

void ext2_delete_inode(struct ext2_inode *inode, uint32_t inum, ext2_fs_t *fs)
{
	inode->dtime = clock_get_posix_time();
	ext2_free_inode_space(inode, fs);
	ext2_update_inode(inode, fs, inum);
	ext2_free_inode(inum, fs);
}

void ext2_close(struct inode *vfs_ino)
{
	struct ext2_inode *inode = ext2_get_inode_from_node(vfs_ino);
	ext2_fs_t *fs = vfs_ino->i_sb->s_helper;

	if(inode->hard_links == 0)
	{
		ext2_delete_inode(inode, (uint32_t) vfs_ino->i_inode, fs);
	}

	free(inode);
}

size_t ext2_write_ino(size_t offset, size_t sizeofwrite, void *buffer, struct inode *node)
{
	ext2_fs_t *fs = node->i_sb->s_helper;
	struct ext2_inode *ino = ext2_get_inode_from_node(node);
	if(!ino)
		return errno = EINVAL, (size_t) -1;

	size_t size = ext2_write_inode(ino, fs, sizeofwrite, offset, buffer);

	if(offset + size > EXT2_CALCULATE_SIZE64(ino))
	{
		ext2_set_inode_size(ino, offset + size);
		node->i_size = offset + size;
	}

	ext2_update_inode(ino, fs, node->i_inode);

	return size;
}

size_t ext2_write(size_t offset, size_t len, void *buf, struct file *f)
{
	return ext2_write_ino(offset, len, buf, f->f_ino);
}

ssize_t ext2_writepage(struct page *page, size_t off, struct inode *ino)
{
	return ext2_write_ino(off, PAGE_SIZE, PAGE_TO_VIRT(page), ino);
}

size_t ext2_read_ino(size_t offset, size_t len, void *buffer, struct inode *node)
{
	//printk("Inode read: %lu, off %lu, size %lu\n", node->i_inode, offset, sizeofreading);
	ext2_fs_t *fs = node->i_sb->s_helper;

	struct ext2_inode *ino = ext2_get_inode_from_node(node);
	if(!ino)
		return errno = EINVAL, -1;

	if(node->i_type == VFS_TYPE_DIR)
	{
		node->i_size = EXT2_CALCULATE_SIZE64(ino);
	}

	if(offset > node->i_size)
		return errno = EINVAL, -1;

	size_t to_be_read = offset + len > node->i_size ?
		node->i_size - offset : len;

	size_t size = ext2_read_inode(ino, fs, to_be_read, offset, buffer);

	return size;
}

size_t ext2_read(size_t offset, size_t sizeofreading, void *buffer, struct file *f)
{
	return ext2_read_ino(offset, sizeofreading, buffer, f->f_ino);
}

ssize_t ext2_readpage(struct page *page, size_t off, struct inode *ino)
{
	return ext2_read_ino(off, PAGE_SIZE, PAGE_TO_VIRT(page), ino);
}

struct ext2_inode_info *ext2_cache_inode_info(struct inode *ino, struct ext2_inode *fs_ino)
{
	struct ext2_inode_info *inf = malloc(sizeof(*inf));
	if(!inf)
		return NULL;
	inf->inode = fs_ino;

	return inf;
}

struct inode *ext2_open(struct file *f, const char *name)
{
	struct inode *nd = f->f_ino;
	ext2_fs_t *fs = nd->i_sb->s_helper;
	uint32_t inode_num;
	struct ext2_inode *ino;
	char *symlink_path = NULL;
	struct inode *node = NULL;

	/* Get the inode structure from the number */
	ino = ext2_get_inode_from_node(nd);	
	if(!ino)
		return NULL;

	ino = ext2_traverse_fs(ino, name, fs, &symlink_path, &inode_num);
	if(!ino)
		return NULL;

	/* See if we have the inode cached in the 	 */
	node = superblock_find_inode(nd->i_sb, inode_num);
	if(node)
	{
		free(ino);
		return node;
	}

	node = ext2_fs_ino_to_vfs_ino(ino, inode_num, f);
	if(!node)
	{
		free(ino);
		spin_unlock(&nd->i_sb->s_ilock);
		return errno = ENOMEM, NULL;
	}

	/* Cache the inode */
	superblock_add_inode_unlocked(nd->i_sb, node);

	spin_unlock(&nd->i_sb->s_ilock);

	return node;
}

struct inode *ext2_fs_ino_to_vfs_ino(struct ext2_inode *inode, uint32_t inumber, struct file *parent)
{
	/* Create a file */
	struct inode *ino = inode_create(ext2_ino_type_to_vfs_type(inode->mode) == VFS_TYPE_FILE);

	if(!ino)
	{
		return NULL;
	}

	ino->i_dev = parent->f_ino->i_dev;
	ino->i_inode = inumber;
	/* Detect the file type */
	ino->i_type = ext2_ino_type_to_vfs_type(inode->mode);
	ino->i_mode = inode->mode;

	/* We're storing dev in dbp[0] in the same format as dev_t */
	ino->i_rdev = inode->dbp[0];

	ino->i_size = EXT2_CALCULATE_SIZE64(inode);
	if(ino->i_type == VFS_TYPE_FILE)
		ino->i_pages->size = ino->i_size;

	ino->i_uid = inode->uid;
	ino->i_gid = inode->gid;
	ino->i_sb = parent->f_ino->i_sb;
	ino->i_atime = inode->atime;
	ino->i_ctime = inode->ctime;
	ino->i_mtime = inode->mtime;
	ino->i_nlink = inode->hard_links;

	ino->i_helper = ext2_cache_inode_info(ino, inode);

	if(!ino->i_helper)
	{
		free(ino);
		return NULL;
	}

	memcpy(&ino->i_fops, &ext2_ops, sizeof(struct file_ops));

	return ino;
}

uint16_t ext2_mode_to_ino_type(mode_t mode)
{
	if(S_ISFIFO(mode))
		return EXT2_INO_TYPE_FIFO;
	if(S_ISCHR(mode))
		return EXT2_INO_TYPE_CHARDEV;
	if(S_ISBLK(mode))
		return EXT2_INO_TYPE_BLOCKDEV;
	if(S_ISDIR(mode))
		return EXT2_INO_TYPE_DIR;
	if(S_ISLNK(mode))
		return EXT2_INO_TYPE_SYMLINK;
	if(S_ISSOCK(mode))
		return EXT2_INO_TYPE_UNIX_SOCK;
	if(S_ISREG(mode))
		return EXT2_INO_TYPE_REGFILE;
	return -1;
}

int ext2_ino_type_to_vfs_type(uint16_t mode)
{
	if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_DIR)
		return VFS_TYPE_DIR;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_REGFILE)
		return VFS_TYPE_FILE;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_BLOCKDEV)
		return VFS_TYPE_BLOCK_DEVICE;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_CHARDEV)
		return VFS_TYPE_CHAR_DEVICE;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_SYMLINK)
		return VFS_TYPE_SYMLINK;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_FIFO)
		return VFS_TYPE_FIFO;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_UNIX_SOCK)
		return VFS_TYPE_UNIX_SOCK;

	/* FIXME: Signal the filesystem as corrupted through the superblock,
	 and don't panic */
	return VFS_TYPE_UNK;
}

struct inode *ext2_create_file(const char *name, mode_t mode, dev_t dev, struct file *f)
{
	struct inode *vfs_ino = f->f_ino;
	ext2_fs_t *fs = vfs_ino->i_sb->s_helper;
	uint32_t inumber = 0;

	struct ext2_inode *inode = ext2_allocate_inode(&inumber, fs);
	struct ext2_inode *dir_inode = ext2_get_inode_from_node(vfs_ino);

	if(!inode)
		return NULL;

	memset(inode, 0, sizeof(struct ext2_inode));
	inode->ctime = inode->atime = inode->mtime = (uint32_t) clock_get_posix_time();
	
	struct creds *c = creds_get();

	inode->uid = c->euid;
	inode->gid = c->egid;

	creds_put(c);

	inode->hard_links = 1;
	uint16_t ext2_file_type = ext2_mode_to_ino_type(mode);
	if(ext2_file_type == (uint16_t) -1)
	{
		errno = EINVAL;
		goto free_ino_error;
	}

	inode->mode = ext2_file_type | (mode & ~S_IFMT);
	
	if(S_ISBLK(mode) || S_ISCHR(mode))
	{
		/* We're a device file, store the device in dbp[0] */
		inode->dbp[0] = dev;
	}

	ext2_update_inode(inode, fs, inumber);
	ext2_update_inode(dir_inode, fs, vfs_ino->i_inode);
	
	if(ext2_add_direntry(name, inumber, inode, dir_inode, fs) < 0)
	{
		errno = EINVAL;
		goto free_ino_error;
	}
	
	struct inode *ino = ext2_fs_ino_to_vfs_ino(inode, inumber, f);
	if(!ino)
	{
		errno = ENOMEM;
		goto unlink_ino;
	}

	superblock_add_inode(vfs_ino->i_sb, ino);

	return ino;

unlink_ino:
	/* TODO: add ext2_unlink() */
	free(ino);
free_ino_error:
	free(inode);
	ext2_free_inode(inumber, fs);

	return NULL;
}

struct inode *ext2_creat(const char *name, int mode, struct file *file)
{
	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

	struct inode *i = ext2_create_file(name, (mode & ~S_IFMT) | S_IFREG, 0, file);

	thread_change_addr_limit(old);

	return i;
}

int ext2_flush_inode(struct inode *inode)
{
	struct ext2_inode *ino = ext2_get_inode_from_node(inode);
	ext2_fs_t *fs = inode->i_sb->s_helper;

	/* Refresh the on-disk struct with the vfs inode data */
	ino->atime = inode->i_atime;
	ino->ctime = inode->i_ctime;
	ino->mtime = inode->i_mtime;
	ino->size_lo = (uint32_t) inode->i_size;
	ino->size_hi = (uint32_t) (inode->i_size >> 32);
	ino->gid = inode->i_gid;
	ino->uid = inode->i_uid;
	ino->hard_links = (uint16_t) inode->i_nlink;
	ino->mode = inode->i_mode;
	ino->uid = inode->i_uid;

	ext2_update_inode(ino, fs, (uint32_t) inode->i_inode);

	return 0;
}

__attribute__((no_sanitize_undefined))
struct inode *ext2_mount_partition(struct blockdev *dev)
{
	LOG("ext2", "mounting ext2 partition on block device %s\n", dev->name);
	superblock_t *sb = malloc(sizeof(superblock_t));
	if(!sb)
		return NULL;
	
	if(blkdev_read(EXT2_SUPERBLOCK_OFFSET, 1024, sb, dev) < 0)
	{
		free(sb);
		return NULL;
	}

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

	struct inode *node = inode_create(false);
	struct ext2_inode *ino = ext2_get_inode_from_number(fs, 2);
	if(!node || !ino)
	{
		if(node)	free(node);
		free(sb);
		free(new_super);
		free(fs->zero_block);
		free(fs);
		return errno = ENOMEM, NULL;
	}

	node->i_inode = 2;
	node->i_type = VFS_TYPE_DIR;
	node->i_sb = new_super;
	node->i_atime = ino->atime;
	node->i_ctime = ino->ctime;
	node->i_mtime = ino->mtime;
	node->i_rdev = 0;
	node->i_gid = ino->gid;
	node->i_uid = ino->uid;
	node->i_mode = ino->mode;
	node->i_helper = ext2_cache_inode_info(node, ino);

	new_super->s_inodes = node;
	new_super->s_helper = fs;
	new_super->flush_inode = ext2_flush_inode;

	memcpy(&node->i_fops, &ext2_ops, sizeof(struct file_ops));
	return node;
}

__init void init_ext2drv()
{
	if(partition_add_handler(ext2_mount_partition, "ext2") == -1)
		FATAL("ext2", "error initializing the handler data\n");
}

off_t ext2_getdirent(struct dirent *buf, off_t off, struct file *this)
{
	off_t new_off;
	dir_entry_t entry;
	size_t read;

	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

	/* Read a dir entry from the offset */
	read = ext2_read(off, sizeof(dir_entry_t), &entry, this);

	thread_change_addr_limit(old);

	/* If we reached the end of the directory buffer, return 0 */
	if(read == 0)
		return 0;

	/* If we reached the end of the directory list, return 0 */
	if(!entry.inode)
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

int ext2_stat(struct stat *buf, struct file *f)
{
	struct inode *node = f->f_ino;
	ext2_fs_t *fs = node->i_sb->s_helper;
	/* Get the inode structure */
	struct ext2_inode *ino = ext2_get_inode_from_node(node);	

	if(!ino)
		return 1;
	/* Start filling the structure */
	buf->st_dev = node->i_dev;
	buf->st_ino = node->i_inode;
	buf->st_nlink = ino->hard_links;
	buf->st_mode = node->i_mode;
	buf->st_uid = node->i_uid;
	buf->st_gid = node->i_gid;
	buf->st_size = node->i_size;
	buf->st_atime = node->i_atime;
	buf->st_mtime = node->i_mtime;
	buf->st_ctime = node->i_ctime;
	buf->st_blksize = fs->block_size;
	buf->st_blocks = node->i_size % 512 ? (node->i_size / 512) + 1 : node->i_size / 512;
	
	return 0;
}

struct inode *ext2_mknod(const char *name, mode_t mode, dev_t dev, struct file *ino)
{
	if(strlen(name) > NAME_MAX)
		return errno = ENAMETOOLONG, NULL;
	
	if(S_ISDIR(mode))
		return errno = EPERM, NULL;
	
	return ext2_create_file(name, mode, dev, ino);
}

struct inode *ext2_mkdir(const char *name, mode_t mode, struct file *f)
{
	struct inode *new_dir = ext2_create_file(name, (mode & 0777) | S_IFDIR, 0, f);
	if(!new_dir)
	{
		return NULL;
	}
	
	/* Create the two basic links - link to self and link to parent */
	/* FIXME: Handle failure here? */
	ext2_link(new_dir, ".", new_dir);
	ext2_link(f->f_ino, "..", new_dir);

	ext2_fs_t *fs = f->f_ino->i_sb->s_helper;

	uint32_t inum = (uint32_t) new_dir->i_inode;
	uint32_t bg = inum / fs->inodes_per_block_group;

	fs->bgdt[bg].used_dirs_count++;
	ext2_register_bgdt_changes(fs);

	return new_dir;
}
