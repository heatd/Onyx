/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/limits.h>
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
#include <onyx/pagecache.h>

#include "ext2.h"

struct inode *ext2_open(struct dentry *dir, const char *name);
off_t ext2_getdirent(struct dirent *buf, off_t off, struct file *f);
struct inode *ext2_creat(const char *path, int mode, struct dentry *dir);
char *ext2_readlink(struct file *ino);
void ext2_close(struct inode *ino);
struct inode *ext2_mknod(const char *name, mode_t mode, dev_t dev, struct dentry *dir);
struct inode *ext2_mkdir(const char *name, mode_t mode, struct dentry *dir);
int ext2_link_fops(struct file *target, const char *name, struct dentry *dir);
int ext2_unlink(const char *name, int flags, struct dentry *dir);
int ext2_fallocate(int mode, off_t off, off_t len, struct file *f);
int ext2_ftruncate(size_t len, struct file *f);
ssize_t ext2_readpage(struct page *page, size_t off, struct inode *ino);
ssize_t ext2_writepage(struct page *page, size_t off, struct inode *ino);
int ext2_prepare_write(inode *ino, struct page *page, size_t page_off, size_t offset, size_t len);
int ext2_link(struct inode *target, const char *name, struct inode *dir);
inode *ext2_symlink(const char *name, const char *dest, dentry *dir);

struct file_ops ext2_ops = 
{
	.open = ext2_open,
	.close = ext2_close,
	.getdirent = ext2_getdirent,
	.creat = ext2_creat,
	.link = ext2_link_fops,
	.symlink = ext2_symlink,
	.ftruncate = ext2_ftruncate,
	.mkdir = ext2_mkdir,
	.mknod = ext2_mknod,
	.readlink = ext2_readlink,
	.unlink = ext2_unlink,
	.fallocate = ext2_fallocate,
	.readpage = ext2_readpage,
	.writepage = ext2_writepage,
	.prepare_write = ext2_prepare_write
};

void ext2_delete_inode(struct inode *inode_, uint32_t inum, struct ext2_superblock *fs)
{
	struct ext2_inode *inode = ext2_get_inode_from_node(inode_);

	inode->dtime = clock_get_posix_time();
	ext2_free_inode_space(inode_, fs);

	inode->hard_links = 0;
	fs->update_inode(inode, inum);

	uint32_t block_group = (inum - 1) / fs->inodes_per_block_group;

	if(S_ISDIR(inode->mode))
		fs->block_groups[block_group].dec_used_dirs();

	fs->free_inode(inum);
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


ssize_t ext2_writepage(page *page, size_t off, inode *ino)
{
	auto buf = block_buf_from_page(page);
	auto sb = ext2_superblock_from_inode(ino);

	assert(buf != nullptr);

	while(buf)
	{
		page_iov v[1];
		v->length = buf->block_size;
		v->page = buf->this_page;
		v->page_off = buf->page_off;

	#if 0
		printk("Writing to block %lu\n", buf->block_nr);
	#endif

		if(sb_write_bio(sb, v, 1, buf->block_nr) < 0)
		{
			sb->error("Error writing back page");
			return -EIO;
		}

		buf = buf->next;
	}

	return PAGE_SIZE;
}

ssize_t ext2_readpage(struct page *page, size_t off, struct inode *ino)
{
	bool is_buffer = page->flags & PAGE_FLAG_BUFFER;

	assert(is_buffer == true);

	auto raw_inode = ext2_get_inode_from_node(ino);
	auto sb = ext2_superblock_from_inode(ino);
	auto nr_blocks = PAGE_SIZE / sb->block_size;
	auto base_block_index = off / sb->block_size;

	auto curr_off = 0;

	for(size_t i = 0; i < nr_blocks; i++)
	{
		struct block_buf *b = nullptr;
		if(is_buffer && !(b = page_add_blockbuf(page, curr_off)))
		{
			page_destroy_block_bufs(page);
			return -ENOMEM;
		}

		auto res = ext2_get_block_from_inode(raw_inode, base_block_index + i, sb);
		if(res.has_error())
		{
			page_destroy_block_bufs(page);
			return -ENOMEM;
		}

		/* TODO: Coalesce reads */
		page_iov v[1];
		v->page = page;
		v->length = sb->block_size;
		v->page_off = curr_off;

		if(sb_read_bio(sb, v, 1, res.value()) < 0)
		{
			page_destroy_block_bufs(page);
			return -EIO;
		}

		if(is_buffer)
		{
			b->block_nr = res.value();
			b->block_size = sb->block_size;
			b->dev = sb->s_bdev;
		}

		curr_off += sb->block_size;
	}

	return min(PAGE_SIZE, ino->i_size - off);
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
	struct inode *ino = dir->d_inode;
	struct ext2_superblock *fs = ext2_superblock_from_inode(ino);
	uint32_t inode_num;

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
	struct inode *ino = inode_create(S_ISDIR(inode->mode) || S_ISREG(inode->mode) || S_ISLNK(inode->mode));

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
	ino->i_rdev = inode->i_data[0];

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

	return VFS_TYPE_UNK;
}

struct inode *ext2_create_file(const char *name, mode_t mode, dev_t dev, struct dentry *dir)
{
	struct inode *vfs_ino = dir->d_inode;
	struct ext2_superblock *fs = ext2_superblock_from_inode(vfs_ino);
	uint32_t inumber = 0;
	struct inode *ino = nullptr;

	auto res = fs->allocate_inode();
	if(res.has_error())
	{
		errno = -res.error();
		return nullptr;
	}

	auto p = res.value();
	inumber = p.first;

	struct ext2_inode *inode = p.second;
	struct ext2_inode *dir_inode = ext2_get_inode_from_node(vfs_ino);

	if(!inode)
		return nullptr;

	memset(inode, 0, sizeof(struct ext2_inode));
	inode->ctime = inode->atime = inode->mtime = (uint32_t) clock_get_posix_time();
	
	struct creds *c = creds_get();
	unsigned long old = 0;

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
		inode->i_data[0] = dev;
	}

	fs->update_inode(inode, inumber);
	fs->update_inode(dir_inode, vfs_ino->i_inode);

	old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
	
	if(int st = ext2_add_direntry(name, inumber, inode, vfs_ino, fs); st < 0)
	{
		thread_change_addr_limit(old);
		printk("ext2 error %d\n", st);
		errno = EINVAL;
		goto free_ino_error;
	}

	if(S_ISDIR(mode)) inode_inc_nlink(vfs_ino);

	thread_change_addr_limit(old);
	
	ino = ext2_fs_ino_to_vfs_ino(inode, inumber, fs);
	if(!ino)
	{
		errno = ENOMEM;
		goto unlink_ino;
	}

	superblock_add_inode(vfs_ino->i_sb, ino);

	return ino;

unlink_ino:
	ext2_unlink(name, 0, dir);
	free(ino);
free_ino_error:
	free(inode);
	fs->free_inode(inumber);

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

	fs->update_inode(ino, (ext2_inode_no) inode->i_inode);

	return 0;
}

int ext2_kill_inode(struct inode *inode)
{
	struct ext2_superblock *fs = ext2_superblock_from_inode(inode);

	ext2_delete_inode(inode, (uint32_t) inode->i_inode, fs);
	return 0;
}

struct inode *ext2_mount_partition(struct blockdev *dev)
{
	LOG("ext2", "mounting ext2 partition on block device %s\n", dev->name);
	ext2_superblock *sb = new ext2_superblock;
	if(!sb)
		return nullptr;

	struct inode *root_inode = nullptr;
	unsigned int block_size = 0;
	unsigned long superblock_block = 0;
	unsigned long sb_off = 0;
	unsigned long entries = 0;
	struct page *page;

	dev->sb = sb;

	sb->s_block_size = EXT2_SUPERBLOCK_OFFSET;
	sb->s_bdev = dev;

	struct block_buf *b = sb_read_block(sb, 1);

	superblock_t *ext2_sb = (superblock_t *) block_buf_data(b);
	
	if(ext2_sb->s_magic == EXT2_SIGNATURE)
		LOG("ext2", "valid ext2 signature detected!\n");
	else
	{
		ERROR("ext2", "invalid ext2 signature %x\n", ext2_sb->s_magic);
		errno = EINVAL;
		block_buf_put(b);
		goto error;
	}

	block_size = 1024 << ext2_sb->s_log_block_size;

	if(block_size > MAX_BLOCK_SIZE)
	{
		ERROR("ext2", "bad block size %u\n", block_size);
		block_buf_put(b);
		goto error;
	}

	/* Since we're re-adjusting the block buffer to be the actual block buffer,
	 * we're deleting this block_buf and grabbing a new one
	 */

	page = b->this_page;
	block_buf_free(b);
	page_destroy_block_bufs(page);
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

	if(ext2_sb->s_rev_level == EXT2_DYNAMIC_REV)
	{
		sb->features_compat = ext2_sb->s_feature_compat;
		sb->features_incompat = ext2_sb->s_feature_incompat;
		sb->features_ro_compat = ext2_sb->s_feature_ro_compat;
		sb->inode_size = ext2_sb->s_inode_size;
	}
	else if(ext2_sb->s_rev_level == EXT2_GOOD_OLD_REV)
	{
		sb->features_compat = 0;
		sb->features_incompat = 0;
		sb->features_ro_compat = 0;
		sb->inode_size = EXT2_GOOD_OLD_INODE_SIZE;
	}
	else
	{
		ERROR("ext2", "couldn't mount: Unknown revision level");
		goto error;
	}

	sb->s_devnr = sb->s_bdev->dev->majorminor;
	sb->sb_bb = b;
	sb->sb = ext2_sb;
	sb->major = ext2_sb->s_rev_level;
	sb->minor = ext2_sb->s_minor_rev_level;
	sb->total_inodes = ext2_sb->s_inodes_count;
	sb->total_blocks = ext2_sb->s_blocks_count;
	sb->block_size = block_size;
	sb->block_size_shift = ilog2(block_size);
	sb->frag_size = 1024 << ext2_sb->s_log_frag_size;
	sb->inode_size = ext2_sb->s_inode_size;
	sb->blocks_per_block_group = ext2_sb->s_blocks_per_group;
	sb->inodes_per_block_group = ext2_sb->s_inodes_per_group;
	sb->number_of_block_groups = sb->total_blocks / sb->blocks_per_block_group;
	entries = sb->block_size / sizeof(uint32_t);
	sb->entry_shift = ilog2(entries);

	if(sb->total_blocks % sb->blocks_per_block_group)
		sb->number_of_block_groups++;

	for(unsigned int i = 0; i < sb->number_of_block_groups; i++)
	{
		ext2_block_group bg{i};
		if(!bg.init(sb))
			goto error;

		if(!sb->block_groups.push_back(cul::move(bg)))
			goto error;
	}


	root_inode = ext2_load_inode_from_disk(2, sb);
	if(!root_inode)
		goto error;

	superblock_add_inode(sb, root_inode);
	sb->flush_inode = ext2_flush_inode;
	sb->kill_inode = ext2_kill_inode;

	sb->sb->s_mtime = clock_get_posix_time();
	sb->sb->s_mnt_count++;

	block_buf_dirty(sb->sb_bb);

	root_inode->i_fops = &ext2_ops;

	return root_inode;
error:
	if(b)   block_buf_put(b);
	delete sb;

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
	ssize_t read;

	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

	/* Read a dir entry from the offset */
	read = file_read_cache(&entry, sizeof(dir_entry_t), f->f_ino, off);
	if(read < 0)
		return read;

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

	new_dir->i_nlink = 2;
	
	/* Create the two basic links - link to self and link to parent */
	/* FIXME: Handle failure here? */
	ext2_link(new_dir, ".", new_dir);
	ext2_link(dir->d_inode, "..", new_dir);

	struct ext2_superblock *fs = ext2_superblock_from_inode(dir->d_inode);

	uint32_t inum = (uint32_t) new_dir->i_inode;

	fs->block_groups[ext2_inode_number_to_bg(inum, fs)].inc_used_dirs();

	inode_mark_dirty(new_dir);

	return new_dir;
}

void ext2_superblock::error(const char *str) const
{
	printk("ext2_error: %s\n", str);

	sb->s_state = EXT2_ERROR_FS;
	block_buf_dirty(sb_bb);
	block_buf_writeback(sb_bb);

	if(sb->s_errors == EXT2_ERRORS_CONTINUE)
		return;
	else if(sb->s_errors == EXT2_ERRORS_PANIC)
		panic("ext2: Panic from previous filesystem error");
	
	/* TODO: Add (re)mouting read-only */
}
