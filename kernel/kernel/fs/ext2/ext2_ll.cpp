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
#include <fcntl.h>

#include <sys/types.h>

#include <onyx/vm.h>
#include <onyx/vfs.h>
#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/log.h>
#include <onyx/panic.h>
#include <onyx/vm.h>
#include <onyx/dentry.h>

#include "ext2.h"

time_t get_posix_time(void);

const unsigned int direct_block_count = 12;

void *ext2_read_block(uint32_t block_index, uint16_t blocks, struct ext2_superblock *fs)
{
	size_t size = blocks * fs->block_size; /* size = nblocks * block size */
	void *buff = nullptr;

	buff = malloc(size); /* Allocate a buffer */
	if(!buff)
		return nullptr;

	size_t read = blkdev_read((size_t) block_index * fs->block_size, size, buff, fs->s_bdev);

	if(read == (size_t) -1)
	{
		free(buff);
		return nullptr;
	}

	return buff;
}

void ext2_read_block_raw(uint32_t block_index, uint16_t blocks, struct ext2_superblock *fs, void *buffer)
{
	size_t size = blocks * fs->block_size; /* size = nblocks * block size */

	blkdev_read(((size_t) block_index) * fs->block_size, size, buffer, fs->s_bdev);
}

void ext2_write_block(uint32_t block_index, uint16_t blocks, struct ext2_superblock *fs, void *buffer)
{
	size_t size = blocks * fs->block_size; /* size = nblocks * block size */
	blkdev_write(block_index * fs->block_size, size, buffer, fs->s_bdev);
}

static inline void __ext2_update_ctime(struct ext2_inode *ino)
{
	ino->ctime = (uint32_t) clock_get_posix_time();
}

ext2_inode *ext2_superblock::get_inode(ext2_inode_no inode) const
{
	uint32_t bg_no = ext2_inode_number_to_bg(inode, this);
	uint32_t index = (inode - 1) % inodes_per_block_group;
	uint32_t inodes_per_block = block_size / inode_size;
	uint32_t block = index / inodes_per_block;
	uint32_t off = (index % inodes_per_block) * inode_size;

	assert(bg_no < number_of_block_groups);

	const auto &bg = block_groups[bg_no];

	auto buf = bg.get_inode_table(this, block);
	if(!buf)
	{
		error("Error reading inode table.");
		return nullptr;
	}

	ext2_inode *ino = (ext2_inode *) malloc(inode_size);

	if(!ino)
		return nullptr;

	ext2_inode *on_disk = (ext2_inode *) ((char *) block_buf_data(buf) + off);

	memcpy(ino, on_disk, inode_size);

	return ino;
}

void ext2_superblock::update_inode(ext2_inode *ino, ext2_inode_no inode_no)
{
	uint32_t bg_no = ext2_inode_number_to_bg(inode_no, this);
	uint32_t index = (inode_no - 1) % inodes_per_block_group;
	uint32_t inodes_per_block = block_size / inode_size;
	uint32_t block = index / inodes_per_block;
	uint32_t off = (index % inodes_per_block) * inode_size;

	assert(bg_no < number_of_block_groups);

	const auto &bg = block_groups[bg_no];

	auto buf = bg.get_inode_table(this, block);
	if(!buf)
	{
		error("Error reading inode table.");
		return;
	}

	ext2_inode *on_disk = (ext2_inode *) ((char *) block_buf_data(buf) + off);

	memcpy(on_disk, ino, inode_size);

	block_buf_dirty(buf);

	return;
}


void ext2_dirty_sb(struct ext2_superblock *fs)
{
	block_buf_dirty(fs->sb_bb);
}

size_t ext2_calculate_dirent_size(size_t len_name)
{
	size_t dirent_size = sizeof(dir_entry_t) - (255 - len_name);

	/* Dirent sizes need to be 4-byte aligned */

	if(dirent_size % 4)
		dirent_size += 4 - dirent_size % 4;

	return dirent_size;
}

uint8_t ext2_file_type_to_type_indicator(uint16_t mode)
{
	if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_DIR)
		return EXT2_FT_DIR;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_REGFILE)
		return EXT2_FT_REG_FILE;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_BLOCKDEV)
		return EXT2_FT_BLKDEV;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_CHARDEV)
		return EXT2_FT_CHRDEV;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_SYMLINK)
		return EXT2_FT_SYMLINK;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_FIFO)
		return EXT2_FT_FIFO;
	else if(EXT2_GET_FILE_TYPE(mode) == EXT2_INO_TYPE_UNIX_SOCK)
		return EXT2_FT_SOCK;
	else
		return EXT2_FT_UNKNOWN;
}

int ext2_add_direntry(const char *name, uint32_t inum, struct ext2_inode *inode,
	struct ext2_inode *dir, struct ext2_superblock *fs)
{
	uint8_t *buffer;
	uint8_t *buf = buffer = (uint8_t *) zalloc(fs->block_size);
	if(!buf)
		return errno = ENOMEM, -1;
	
	size_t off = 0;

	dir_entry_t entry;
	
	size_t dirent_size = ext2_calculate_dirent_size(strlen(name));

	entry.inode = inum;
	assert(entry.inode != 0);
	entry.lsbit_namelen = strlen(name);

	entry.type_indic = ext2_file_type_to_type_indicator(inode->mode);

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
				
				if(e->inode == 0 && e->size >= dirent_size)
				{
					/* This direntry is unused, so use it */
					e->inode = entry.inode;
					e->lsbit_namelen = entry.lsbit_namelen;
					strlcpy(e->name, entry.name, sizeof(entry.name));
					e->type_indic = entry.type_indic;

					COMPILER_BARRIER();

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
				else if(e->size > actual_size && 
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

void ext2_unlink_dirent(dir_entry_t *before, dir_entry_t *entry)
{
	/* If we're not the first dirent on the block, adjust the reclen
	 * so it points to the next dirent(or the end of the block).
	*/
	dir_entry_t *next = (dir_entry_t *)((char *) entry + entry->size);

	if(before)
	{
		#if 0
		printk("Old size: %u\n", before->size);
		printk("Next: %p\nBefore: %p\n", next, before);
		#endif
		before->size = (unsigned long) next - (unsigned long) before;
		#if 0
		printk("New size: %u\n", before->size);
		#endif
	}
	
	/* Mark the entry as unused */
	entry->inode = 0;
}

int ext2_remove_direntry(uint32_t inum, struct ext2_inode *dir, struct ext2_superblock *fs)
{
	int st = -ENOENT;
	uint8_t *buf_start;
	uint8_t *buf = buf_start = (uint8_t *) zalloc(fs->block_size);
	if(!buf)
		return errno = ENOMEM, -1;
	
	size_t off = 0;

	while(off < EXT2_CALCULATE_SIZE64(dir))
	{
		ext2_read_inode(dir, fs, fs->block_size, (size_t) off, (char*) buf);

		dir_entry_t *before = nullptr;
		for(size_t i = 0; i < fs->block_size; )
		{
			dir_entry_t *e = (dir_entry_t *) buf;

			if(e->inode == inum)
			{
				/* We found the inode, unlink it. */
				ext2_unlink_dirent(before, e);
				ext2_write_inode(dir, fs, fs->block_size, off, (char *) buf);
				st = 0;
				goto out;
			}

			before = e;
			buf += e->size;
			i += e->size;
		}

		off += fs->block_size;
		buf = buf_start;
	}

out:
	free(buf_start);
	return st;
}

int ext2_file_present(struct ext2_inode *inode, const char *name, struct ext2_superblock *fs)
{
	int st = 0;
	char *buf = (char *) zalloc(fs->block_size);
	if(!buf)
		return -ENOMEM;

	off_t off = 0;

	while((size_t) off < EXT2_CALCULATE_SIZE64(inode))
	{
		unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

		ssize_t res = ext2_read_inode(inode, fs, fs->block_size, off, buf);

		thread_change_addr_limit(old);

		if(res < 0)
		{
			st = -EIO;
			goto out;
		}

		for(char *b = buf; b < buf + fs->block_size; )
		{
			dir_entry_t *entry = (dir_entry_t *) b;

			if(entry->lsbit_namelen == strlen(name) && 
		  	   !memcmp(entry->name, name, entry->lsbit_namelen))
			{
				st = 1;
				goto out;
			}

			b += entry->size;
		}

		off += fs->block_size;
	}

out:
	free(buf);
	return st;
}

int ext2_retrieve_dirent(struct ext2_inode *inode, const char *name, struct ext2_superblock *fs,
			 struct ext2_dirent_result *res)
{
	int st = -ENOENT;
	char *buf = static_cast<char *>(zalloc(fs->block_size));
	if(!buf)
		return -ENOMEM;

	off_t off = 0;

	while((size_t) off < EXT2_CALCULATE_SIZE64(inode))
	{
		ssize_t read_res = ext2_read_inode(inode, fs, fs->block_size, off, buf);

		if(read_res < 0)
		{
			st = -EIO;
			goto out;
		}

		for(char *b = buf; b < buf + fs->block_size; )
		{
			dir_entry_t *entry = (dir_entry_t *) b;

			if(entry->lsbit_namelen == strlen(name) && 
		  	   !memcmp(entry->name, name, entry->lsbit_namelen))
			{
				res->block_off = b - buf;
				res->file_off = off + res->block_off;
				res->buf = buf;
				st = 1;
				goto out;
			}

			b += entry->size;
		}

		off += fs->block_size;
	}

out:
	if(st != 1) free(buf);
	return st;
}

int ext2_link(struct inode *target, const char *name, struct inode *dir)
{
	assert(target->i_sb == dir->i_sb);

	struct ext2_superblock *fs = ext2_superblock_from_inode(dir);

	struct ext2_inode *inode = ext2_get_inode_from_node(dir);
	struct ext2_inode *target_ino = ext2_get_inode_from_node(target);

	int st = ext2_file_present(inode, name, fs);
	if(st < 0)
	{
		return st;
	}
	else if(st == 1)
	{
		return -EEXIST;
	}

	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

	/* Blame past me for the inconsistency in return values */
	st = ext2_add_direntry(name, (uint32_t) target->i_inode, target_ino, inode, fs);

	thread_change_addr_limit(old);

	if(st < 0)
	{
		return -errno;
	}

	__sync_fetch_and_add(&target_ino->hard_links, 1);
	__sync_synchronize();
	COMPILER_BARRIER();

	fs->update_inode(target_ino, (ext2_inode_no) target->i_inode);

	return 0;
}

int ext2_link_fops(struct file *_target, const char *name, struct dentry *_dir)
{
	return ext2_link(_target->f_ino, name, _dir->d_inode);
}

struct inode *ext2_load_inode_from_disk(uint32_t inum, struct ext2_superblock *fs)
{
	struct ext2_inode *inode = fs->get_inode(inum);
	if(!inode)
		return nullptr;
	
	struct inode *node = ext2_fs_ino_to_vfs_ino(inode, inum, fs);
	if(!node)
	{
		free(inode);
		return errno = ENOMEM, nullptr;
	}

	return node;
}

bool ext2_is_standard_dir_link(dir_entry_t *entry)
{
	if(!memcmp(entry->name, ".", entry->lsbit_namelen))
		return true;
	if(!memcmp(entry->name, "..", entry->lsbit_namelen))
		return true;
	return false;
}

int ext2_dir_empty(struct inode *ino)
{
	struct ext2_inode *inode = ext2_get_inode_from_node(ino);
	struct ext2_superblock *fs = ext2_superblock_from_inode(ino);

	int st = 1;
	char *buf = (char *) zalloc(fs->block_size);
	if(!buf)
		return -ENOMEM;

	off_t off = 0;

	while((size_t) off < EXT2_CALCULATE_SIZE64(inode))
	{
		unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

		ssize_t res = ext2_read_inode(inode, fs, fs->block_size, off, buf);

		thread_change_addr_limit(old);

		if(res < 0)
		{
			st = -EIO;
			goto out;
		}

		for(char *b = buf; b < buf + fs->block_size; )
		{
			dir_entry_t *entry = (dir_entry_t *) b;

			if(entry->inode != 0 && !ext2_is_standard_dir_link(entry))
			{
				st = 0;
				goto out;
			}

			b += entry->size;
		}

		off += fs->block_size;
	}

out:
	free(buf);
	return st;
}

int ext2_unlink(const char *name, int flags, struct dentry *dir)
{
	struct inode *ino = dir->d_inode;
	struct ext2_superblock *fs = ext2_superblock_from_inode(ino);

	struct ext2_inode *inode = ext2_get_inode_from_node(ino);

	struct ext2_dirent_result res;
	int st = ext2_retrieve_dirent(inode, name, fs, &res);

	if(st < 0)
	{
		free(res.buf);
		return st;
	}
	else if(st == 0)
	{
		return -ENOENT;
	}

	dir_entry_t *ent = (dir_entry_t *) (res.buf + res.block_off);
	
	struct inode *target = superblock_find_inode(ino->i_sb, ent->inode);

	/* TODO: target is forced to exist; pass dentry and optimise this, maybe */
	assert(target != nullptr);

	if(target->i_type == VFS_TYPE_DIR)
	{
		if(!(flags & AT_REMOVEDIR))
		{
			free(res.buf);
			return -EISDIR;
		}

		if(ext2_dir_empty(target) == 0)
		{
			free(res.buf);
			return -ENOTEMPTY;
		}
	}

	dir_entry_t *before = nullptr;

	/* Now, unlink the dirent */
	if(res.block_off != 0)
	{
		for(char *b = res.buf; b < res.buf + res.block_off;)
		{
			dir_entry_t *dir = (dir_entry_t *) b;
			if((b - res.buf) + dir->size == res.block_off)
			{
				before = dir;
				break;
			}

			b += dir->size;
		}

		assert(before != nullptr);
	}

	ext2_unlink_dirent(before, (dir_entry_t *) (res.buf + res.block_off));

	/* Flush to disk */
	/* TODO: Maybe we can optimize things by not flushing the whole block? */
	if(ext2_write_inode(inode, fs, fs->block_size, res.file_off - res.block_off, res.buf) < 0)
	{
		close_vfs(target);
		return -EIO;
	}

	free(res.buf);

	close_vfs(target);

	return 0;
}

int ext2_fallocate(int mode, off_t off, off_t len, struct file *ino)
{
	return -ENOSYS;
}
