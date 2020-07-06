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
#include <onyx/buffer.h>
#include <onyx/dentry.h>

#include "ext2.h"

struct inode *ext2_open(struct dentry *dir, const char *name);
size_t ext2_read(size_t offset, size_t sizeofreading, void *buffer, struct file *node);
off_t ext2_getdirent(struct dirent *buf, off_t off, struct file *f);
struct inode *ext2_creat(const char *path, int mode, struct dentry *dir);
char *ext2_readlink(struct file *ino);
void ext2_close(struct inode *ino);
struct inode *ext2_mknod(const char *name, mode_t mode, dev_t dev, struct dentry *dir);
struct inode *ext2_mkdir(const char *name, mode_t mode, struct dentry *dir);
int ext2_link_fops(struct file *target, const char *name, struct dentry *dir);
int ext2_unlink(const char *name, int flags, struct dentry *dir);
int ext2_fallocate(int mode, off_t off, off_t len, struct file *f);
int ext2_ftruncate(off_t off, struct file *f);
ssize_t ext2_readpage(struct page *page, size_t off, struct inode *ino);
ssize_t ext2_writepage(struct page *page, size_t off, struct inode *ino);

int ext2_link(struct inode *target, const char *name, struct inode *dir);

struct file_ops ext2_ops = 
{
	.open = ext2_open,
	.close = ext2_close,
	.getdirent = ext2_getdirent,
	.creat = ext2_creat,
	.link = ext2_link_fops,
	.mkdir = ext2_mkdir,
	.mknod = ext2_mknod,
	.readlink = ext2_readlink,
	.unlink = ext2_unlink,
	.fallocate = ext2_fallocate,
	//.ftruncate = ext2_ftruncate,
	.readpage = ext2_readpage,
	.writepage = ext2_writepage
};

void ext2_delete_inode(struct ext2_inode *inode, uint32_t inum, struct ext2_superblock *fs)
{
	inode->dtime = clock_get_posix_time();
	ext2_free_inode_space(inode, fs);

	inode->hard_links = 0;
	ext2_update_inode(inode, fs, inum);

	uint32_t block_group = inum / fs->inodes_per_block_group;

	if(S_ISDIR(inode->mode))
		fs->bgdt[block_group].used_dirs_count--;
	
	ext2_register_bgdt_changes(fs);

	ext2_free_inode(inum, fs);
}

void ext2_close(struct inode *vfs_ino)
{
	struct ext2_inode *inode = ext2_get_inode_from_node(vfs_ino);

	/* TODO: It would be better, cache-wise and memory allocator-wise if we
	 * had ext2_inode incorporate a struct inode inside it, and have everything in the same location.
	 * TODO: We're also storing a lot of redudant info in ext2_inode(we already have most stuff in
	 * the regular struct inode).
	 */
	free(inode);
}

size_t ext2_write_ino(size_t offset, size_t sizeofwrite, void *buffer, struct inode *node)
{
	struct ext2_superblock *fs = ext2_superblock_from_inode(node);
	struct ext2_inode *ino = ext2_get_inode_from_node(node);
	if(!ino)
		return errno = EINVAL, (size_t) -1;

	size_t size = ext2_write_inode(ino, fs, sizeofwrite, offset, static_cast<char *>(buffer));

	return size;
}

ssize_t ext2_writepage(struct page *page, size_t off, struct inode *ino)
{
	return ext2_write_ino(off, PAGE_SIZE, PAGE_TO_VIRT(page), ino);
}

size_t ext2_read_ino(size_t offset, size_t len, void *buffer, struct inode *node)
{
	// printk("Inode read: %lu, off %lu, size %lu\n", node->i_inode, offset, len);
	struct ext2_superblock *fs = ext2_superblock_from_inode(node);

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

	size_t size = ext2_read_inode(ino, fs, to_be_read, offset, static_cast<char *>(buffer));

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
	struct ext2_inode_info *inf = new ext2_inode_info;
	if(!inf)
		return nullptr;

	inf->inode = fs_ino;

	return inf;
}

inode *ext2_get_inode(ext2_superblock *sb, uint32_t inode_num)
{
	/* First we try to find the inode in the cache, if it's not there,
	 * we unlock the lock and try and read it in. Then we retry to read
	 * from the hashtable, and if it's there we free the one we read;
	 * if not, we insert and return ours.
	 */

	auto ino = superblock_find_inode(sb, inode_num);

	if(ino)
		return ino;
	
	inode_unlock_hashtable(sb, inode_num);

	ino = ext2_load_inode_from_disk(inode_num, sb);

	if(!ino)
		return nullptr;
	
	auto new_ = superblock_find_inode(sb, inode_num);

	if(new_)
	{
		free(ino->i_helper);
		delete ino;
		return new_;
	}

	superblock_add_inode_unlocked(sb, ino);

	return ino;
}

struct inode *ext2_open(struct dentry *dir, const char *name)
{
	struct inode *nd = dir->d_inode;
	struct ext2_superblock *fs = ext2_superblock_from_inode(nd);
	uint32_t inode_num;
	struct ext2_inode *ino;

	/* Get the inode structure from the number */
	ino = ext2_get_inode_from_node(nd);	
	if(!ino)
		return nullptr;

	struct ext2_dirent_result res;
	int st = ext2_retrieve_dirent(ino, name, fs, &res);

	if(st < 0)
	{
		return errno = -st, nullptr;
	}

	dir_entry_t *dentry = (dir_entry_t *) (res.buf + res.block_off);

	inode_num = dentry->inode;

	free(res.buf);


	return ext2_get_inode(fs, inode_num);
}

struct inode *ext2_fs_ino_to_vfs_ino(struct ext2_inode *inode, uint32_t inumber, ext2_superblock *sb)
{
	/* Create a file */
	struct inode *ino = inode_create(ext2_ino_type_to_vfs_type(inode->mode) == VFS_TYPE_FILE);

	if(!ino)
	{
		return nullptr;
	}

	/* Possible when mounting the root inode */
	if(sb)
	{
		ino->i_dev = sb->s_devnr;
		ino->i_sb = sb;
	}

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
	ino->i_atime = inode->atime;
	ino->i_ctime = inode->ctime;
	ino->i_mtime = inode->mtime;
	ino->i_nlink = inode->hard_links;
	ino->i_blocks = inode->i_blocks;

	ino->i_helper = ext2_cache_inode_info(ino, inode);

	if(!ino->i_helper)
	{
		free(ino);
		return nullptr;
	}

	ino->i_fops = &ext2_ops;

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

struct inode *ext2_create_file(const char *name, mode_t mode, dev_t dev, struct dentry *dir)
{
	struct inode *vfs_ino = dir->d_inode;
	struct ext2_superblock *fs = ext2_superblock_from_inode(vfs_ino);
	uint32_t inumber = 0;
	struct inode *ino = nullptr;

	struct ext2_inode *inode = ext2_allocate_inode(&inumber, fs);
	struct ext2_inode *dir_inode = ext2_get_inode_from_node(vfs_ino);

	if(!inode)
		return nullptr;

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
	
	ino = ext2_fs_ino_to_vfs_ino(inode, inumber, fs);
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

	return nullptr;
}

struct inode *ext2_creat(const char *name, int mode, struct dentry *dir)
{
	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

	struct inode *i = ext2_create_file(name, (mode & ~S_IFMT) | S_IFREG, 0, dir);

	thread_change_addr_limit(old);

	return i;
}

int ext2_flush_inode(struct inode *inode)
{
	struct ext2_inode *ino = ext2_get_inode_from_node(inode);
	struct ext2_superblock *fs = ext2_superblock_from_inode(inode);

	/* Refresh the on-disk struct with the vfs inode data */
	ino->atime = inode->i_atime;
	ino->ctime = inode->i_ctime;
	ino->mtime = inode->i_mtime;
	ino->size_lo = (uint32_t) inode->i_size;
	ino->size_hi = (uint32_t) (inode->i_size >> 32);
	ino->gid = inode->i_gid;
	ino->uid = inode->i_uid;
	ino->hard_links = (uint16_t) inode->i_nlink;
	ino->i_blocks = (uint32_t) inode->i_blocks;
	ino->mode = inode->i_mode;
	ino->uid = inode->i_uid;

	ext2_update_inode(ino, fs, (uint32_t) inode->i_inode);

	return 0;
}

int ext2_kill_inode(struct inode *inode)
{
	struct ext2_superblock *fs = ext2_superblock_from_inode(inode);
	struct ext2_inode *ext2_inode_ = ext2_get_inode_from_node(inode);

	ext2_delete_inode(ext2_inode_, (uint32_t) inode->i_inode, fs);
	return 0;
}

struct inode *ext2_mount_partition(struct blockdev *dev)
{
	LOG("ext2", "mounting ext2 partition on block device %s\n", dev->name);
	ext2_superblock *sb = new ext2_superblock;
	if(!sb)
		return nullptr;

	struct inode *root_inode = nullptr;
	struct ext2_inode *disk_root_ino = nullptr;
	unsigned int block_size = 0;
	unsigned long superblock_block = 0;
	unsigned long sb_off = 0;
	unsigned long entries = 0;
	block_group_desc_t *bgdt = nullptr;
	size_t blocks_for_bgdt = 0;

	dev->sb = sb;

	sb->s_block_size = EXT2_SUPERBLOCK_OFFSET;
	sb->s_bdev = dev;

	struct block_buf *b = sb_read_block(sb, 1);

	superblock_t *ext2_sb = (superblock_t *) block_buf_data(b);
	
	ext2_sb->ext2sig = EXT2_SIGNATURE;

	if(ext2_sb->ext2sig == EXT2_SIGNATURE)
		LOG("ext2", "valid ext2 signature detected!\n");
	else
	{
		ERROR("ext2", "invalid ext2 signature %x\n", ext2_sb->ext2sig);
		errno = EINVAL;
		block_buf_put(b);
		goto error;
	}

	block_buf_dirty(b);

	block_size = 1024 << ext2_sb->log2blocksz;

	if(block_size > MAX_BLOCK_SIZE)
	{
		ERROR("ext2", "bad block size %u\n", block_size);
		block_buf_put(b);
		goto error;
	}

	/* Since we're re-adjusting the block buffer to be the actual block buffer,
	 * we're deleting this block_buf and grabbing a new one
	 */

	block_buf_free(b);
	b = nullptr;
	sb->s_block_size = block_size;
	superblock_block = block_size == 1024 ? 1 : 0;
	sb_off = EXT2_SUPERBLOCK_OFFSET & (block_size - 1);

	b = sb_read_block(sb, superblock_block);

	if(!b)
	{
		/* :( riperino the bufferino */
		goto error;
	}

	ext2_sb = (superblock_t *)((char *) block_buf_data(b) + sb_off);

	mutex_init(&sb->bgdt_lock);
	mutex_init(&sb->ino_alloc_lock);
	mutex_init(&sb->sb_lock);

	sb->s_devnr = sb->s_bdev->dev->majorminor;
	sb->sb_bb = b;
	sb->sb = ext2_sb;
	sb->major = ext2_sb->major_version;
	sb->minor = ext2_sb->minor_version;
	sb->total_inodes = ext2_sb->total_inodes;
	sb->total_blocks = ext2_sb->total_blocks;
	sb->block_size = block_size;
	sb->frag_size = 1024 << ext2_sb->log2fragsz;
	sb->inode_size = ext2_sb->size_inode_bytes;
	sb->blkdevice = dev;
	sb->blocks_per_block_group = ext2_sb->blockgroupblocks;
	sb->inodes_per_block_group = ext2_sb->blockgroupinodes;
	sb->number_of_block_groups = sb->total_blocks / sb->blocks_per_block_group;
	entries = sb->block_size / sizeof(uint32_t);
	sb->entry_shift = 31 - __builtin_clz(entries);

	if (sb->total_blocks % sb->blocks_per_block_group)
		sb->number_of_block_groups++;
	/* The driver keeps a block sized zero'd mem chunk for easy and fast overwriting of blocks */
	sb->zero_block = zalloc(sb->block_size);
	if(!sb->zero_block)
	{
		goto error;
	}

	blocks_for_bgdt = (sb->number_of_block_groups *
		sizeof(block_group_desc_t)) / sb->block_size;

	if((sb->number_of_block_groups * sizeof(block_group_desc_t)) % sb->block_size)
		blocks_for_bgdt++;
	if(sb->block_size == 1024)
		bgdt = (block_group_desc_t *) ext2_read_block(2, (uint16_t) blocks_for_bgdt, sb);
	else
		bgdt = (block_group_desc_t *) ext2_read_block(1, (uint16_t) blocks_for_bgdt, sb);
	sb->bgdt = bgdt;

	disk_root_ino = ext2_get_inode_from_number(sb, 2);
	if(!disk_root_ino)
	{
		goto error;
	}

	root_inode = ext2_fs_ino_to_vfs_ino(disk_root_ino, 2, sb);
	if(!root_inode)
	{
		free(disk_root_ino);
		goto error;
	}

	superblock_add_inode(sb, root_inode);
	sb->flush_inode = ext2_flush_inode;
	sb->kill_inode = ext2_kill_inode;

	root_inode->i_fops = &ext2_ops;

	return root_inode;
error:
	if(b)   block_buf_put(b);
	if(sb)
	{
		if(sb->zero_block)
			free(sb->zero_block);
		
		free(sb);
	}

	return nullptr;
}

__init void init_ext2drv()
{
	if(partition_add_handler(ext2_mount_partition, "ext2") == -1)
		FATAL("ext2", "error initializing the handler data\n");
}

off_t ext2_getdirent(struct dirent *buf, off_t off, struct file *f)
{
	off_t new_off;
	dir_entry_t entry;
	size_t read;

	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

	/* Read a dir entry from the offset */
	read = ext2_read(off, sizeof(dir_entry_t), &entry, f);

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

struct inode *ext2_mknod(const char *name, mode_t mode, dev_t dev, struct dentry *dir)
{
	return ext2_create_file(name, mode, dev, dir);
}

struct inode *ext2_mkdir(const char *name, mode_t mode, struct dentry *dir)
{
	struct inode *new_dir = ext2_create_file(name, (mode & 0777) | S_IFDIR, 0, dir);
	if(!new_dir)
	{
		return nullptr;
	}
	
	/* Create the two basic links - link to self and link to parent */
	/* FIXME: Handle failure here? */
	ext2_link(new_dir, ".", new_dir);
	ext2_link(dir->d_inode, "..", new_dir);

	struct ext2_superblock *fs = ext2_superblock_from_inode(dir->d_inode);

	uint32_t inum = (uint32_t) new_dir->i_inode;
	uint32_t bg = inum / fs->inodes_per_block_group;

	fs->bgdt[bg].used_dirs_count++;
	ext2_register_bgdt_changes(fs);

	return new_dir;
}
