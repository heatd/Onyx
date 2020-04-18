/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <onyx/tmpfs.h>
#include <onyx/log.h>
#include <onyx/vfs.h>
#include <onyx/mutex.h>
#include <onyx/page.h>
#include <onyx/dev.h>

static struct mutex tmpfs_list_lock;
static tmpfs_filesystem_t *filesystems = NULL;
static const size_t block_size = PAGE_SIZE; 

static void tmpfs_set_node_fileops(struct inode *node);

static void tmpfs_append(tmpfs_filesystem_t *fs)
{
	mutex_lock(&tmpfs_list_lock);

	tmpfs_filesystem_t **p = &filesystems;

	while(*p)
	{
		tmpfs_filesystem_t *f = *p;
		p = &(f->next);
	}
	*p = fs;

	mutex_unlock(&tmpfs_list_lock);
}

int tmpfs_symlink(const char *dest, struct file *f)
{
	tmpfs_file_t *file = (tmpfs_file_t *) f->f_ino->i_inode;

	char *str = strdup(dest);
	if(!str)
		return -1;
	file->symlink = (const char *) str;
	file->type = TMPFS_FILE_TYPE_SYM;
	f->f_ino->i_type = VFS_TYPE_SYMLINK;

	return 0;
}

static void tmpfs_append_file(tmpfs_file_t *dir, tmpfs_file_t *file)
{
	mutex_lock(&dir->dirent_lock);
	
	tmpfs_file_t **f = &dir->child;
	while(*f)
	{
		tmpfs_file_t *_f = *f;
		f = &(_f->sibblings);
	}
	*f = file;

	mutex_unlock(&dir->dirent_lock);
}

tmpfs_file_t *tmpfs_create_file(tmpfs_file_t *dir, const char *name)
{
	/* Create the file structure */
	tmpfs_file_t *file = zalloc(sizeof(tmpfs_file_t));
	if(!file)
		return NULL;

	file->name = strdup(name);
	if(!file->name)
		goto error;
	
	tmpfs_append_file(dir, file);

	return file;
error:
	free(file);
	return NULL;
}

struct inode *tmpfs_file_to_vfs(tmpfs_file_t *file, struct file *parent)
{
	struct inode *f = inode_create(file->type == TMPFS_FILE_TYPE_REG);
	if(!f)
		return NULL;
	switch(file->type)
	{
		case TMPFS_FILE_TYPE_DIR:
			f->i_type = VFS_TYPE_DIR;
			break;
		case TMPFS_FILE_TYPE_REG:
			f->i_type = VFS_TYPE_FILE;
			break;
		case TMPFS_FILE_TYPE_SYM:
			f->i_type = VFS_TYPE_SYMLINK;
			break;
		case TMPFS_FILE_TYPE_CHAR:
			f->i_type = VFS_TYPE_CHAR_DEVICE;
			break;
		case TMPFS_FILE_TYPE_BLOCK:
			f->i_type = VFS_TYPE_BLOCK_DEVICE;
			break;
	}

	f->i_mode = file->mode;
	f->i_uid = file->st_uid;
	f->i_gid = file->st_gid;

	f->i_rdev = file->rdev;
	f->i_helper = parent->f_ino->i_helper;

	if(f->i_rdev)
	{
		struct dev *d = dev_find(f->i_rdev);
		assert(d != NULL);
		memcpy(&f->i_fops, &d->fops, sizeof(struct file_ops));
		f->i_helper = d->priv;
	}
	else
		tmpfs_set_node_fileops(f);

	f->i_inode = (ino_t) file;
	f->i_size = file->size;
	if(f->i_type == VFS_TYPE_FILE)
		f->i_pages->size = f->i_size;
	f->i_sb = tmpfs_get_root(parent)->superblock;

	return f;
}

struct inode *tmpfs_creat(const char *pathname, int mode, struct file *f)
{
	tmpfs_file_t *file = (tmpfs_file_t *) f->f_ino->i_inode;

	assert(file != NULL);

	tmpfs_file_t *new_file = tmpfs_create_file(file, pathname);
	if(!new_file)
		return NULL;

	new_file->mode = mode;
	new_file->type = TMPFS_FILE_TYPE_REG;

	struct inode *in = tmpfs_file_to_vfs(new_file, f);
	if(!in)
		return NULL;
	
	superblock_add_inode(f->f_ino->i_sb, in);

	return in;
}

ssize_t tmpfs_read_block(tmpfs_file_t *file, size_t block, char *buf)
{
	tmpfs_data_block_t *blk = file->data;
	for(size_t i = 0; i < block; i++)
	{
		if(!blk)
			return 0;		
		blk = blk->next;
	}
	
	if(!blk)
		return 0;
	
	memcpy(buf, &blk->data, block_size);
	return block_size;
}

size_t tmpfs_read_ino(size_t offset, size_t size, void *buffer, struct inode *ino)
{
	tmpfs_file_t *file = (tmpfs_file_t *) ino->i_inode;

	struct page *p = alloc_page(0);
	if(!p)
		return errno = ENOMEM, (size_t) -1;

	char *scratch = PAGE_TO_VIRT(p);
	ssize_t read = 0;
	while(read != (ssize_t) size)
	{
		size_t block = offset / block_size;
		off_t block_off = offset % block_size;
		off_t block_left = block_size - block_off;
		
		/* TODO: We shouldn't need a scratch page, should we? Investigate. */
		if(!tmpfs_read_block(file, block, scratch))
		{
			free_page(p);
			return read;
		}

		size_t amount = (ssize_t) (size - read) < block_left ? (ssize_t) size - read : block_left;
		if(offset + amount > ino->i_size)
		{
			amount = ino->i_size - offset;
			if(copy_to_user(buffer + read, scratch + block_off, amount) < 0)
				read = -EFAULT;
			read += amount;
			free_page(p);
			return read;
		}
		else
		{
			if(copy_to_user(buffer + read, scratch + block_off, amount) < 0)
			{
				free_page(p);
				return -EFAULT;
			}
		}
	
		read += amount;
		offset += amount;
	}

	free_page(p);
	return read;
}

size_t tmpfs_read(size_t offset, size_t size, void *buffer, struct file *f)
{
	return tmpfs_read_ino(offset, size, buffer, f->f_ino);
}

ssize_t tmpfs_readpage(struct page *page, size_t off, struct inode *ino)
{
	return tmpfs_read_ino(off, PAGE_SIZE, PAGE_TO_VIRT(page), ino);
}

size_t tmpfs_write(size_t offset, size_t size, void *buffer, struct file *vnode)
{
	/* We don't write anything since it should be cached anyway */
	return size;
}

ssize_t tmpfs_writepage(struct page *page, size_t off, struct inode *ino)
{
	return PAGE_SIZE;
}

static void tmpfs_append_data(tmpfs_data_block_t *block, tmpfs_file_t *file)
{
	mutex_lock(&file->data_lock);
	tmpfs_data_block_t **p = &file->data;
	
	while(*p)
	{
		tmpfs_data_block_t *f = *p;
		p = &(f->next);
	}
	*p = block;
	
	mutex_unlock(&file->data_lock);
}

static int tmpfs_add_block(const char *buf, size_t size, tmpfs_file_t *file)
{
	tmpfs_data_block_t *block = zalloc(sizeof(tmpfs_data_block_t) + block_size);
	if(!block)
		return -1;
	tmpfs_append_data(block, file);
	assert(size <= block_size);
	memcpy(&block->data, buf, size);
	return 0;
}

int tmpfs_fill_with_data(struct file *f, const void *_buf, size_t size)
{
	struct inode *ino = f->f_ino;
	tmpfs_file_t *file = (tmpfs_file_t *) ino->i_inode;
	
	const char *buf = _buf;
	size_t nr_reads = vm_size_to_pages(size);
	off_t off = 0;

	for(size_t i = 0; i < nr_reads; i++)
	{
		size_t sz = size - off < block_size ? size - off : block_size; 
		if(tmpfs_add_block(buf, sz, file) < 0)
			return errno = ENOSPC, -1;
		file->size += sz;
		ino->i_size += sz;
		buf += sz;
		off += block_size;
	}

	return 0;
}

void tmpfs_debug(tmpfs_file_t *dir)
{
	tmpfs_file_t *f = dir->child;
	while(f)
	{
		printk("%s ", f->name);
		f = f->sibblings;
	}
	printk("\n");
}

tmpfs_file_t *tmpfs_open_file(tmpfs_file_t *dir, const char *name)
{
	tmpfs_file_t **f = &dir->child;

	while(*f)
	{
		tmpfs_file_t *file = *f;
		if(!strcmp(file->name, name))
			return file;
		f = &file->sibblings;
	}

	return errno = ENOENT, NULL;
}

struct inode *tmpfs_mkdir(const char *name, mode_t mode, struct file *f)
{
	struct inode *ino = f->f_ino;
	tmpfs_file_t *file = (tmpfs_file_t *) ino->i_inode;
	
	assert(file != NULL);
	
	if(tmpfs_open_file(file, name))
		return errno = EEXIST, NULL;

	tmpfs_file_t *new_file = tmpfs_create_file(file, name);
	if(!new_file)
		return NULL;

	new_file->mode = mode;
	new_file->type = TMPFS_FILE_TYPE_DIR;
	
	struct inode *in = tmpfs_file_to_vfs(new_file, f);
	if(!in)
		return NULL;
	
	superblock_add_inode(ino->i_sb, in);

	return in;
}

struct inode *tmpfs_find_inode_in_cache(struct file *vnode, tmpfs_file_t *file)
{
	tmpfs_filesystem_t *fs = tmpfs_get_root(vnode);
	
	assert(fs != NULL);

	/* Try to find the inode */
	struct inode *inode = superblock_find_inode(fs->superblock, (ino_t) file);

	if(inode)
		return inode;
	
	/* If we found it, great, else, create a new struct file and add it to
	 * the cache */
	inode = tmpfs_file_to_vfs(file, vnode);

	if(!inode)
	{
		spin_unlock(&fs->superblock->s_ilock);
		return NULL;
	}
	
	superblock_add_inode_unlocked(fs->superblock, inode);

	spin_unlock(&fs->superblock->s_ilock);
	return inode;
}

struct inode *tmpfs_open(struct file *f, const char *name)
{
	struct inode *ino = f->f_ino;
	tmpfs_file_t *dir = (tmpfs_file_t *) ino->i_inode;

	assert(dir != NULL);

	tmpfs_file_t *file = tmpfs_open_file(dir, name);
	if(!file)
		return NULL;

	return tmpfs_find_inode_in_cache(f, file);
}

struct inode *tmpfs_mknod(const char *name, mode_t mode, dev_t dev, struct file *root)
{
	struct inode *ino = root->f_ino;
	tmpfs_file_t *dir = (tmpfs_file_t *) ino->i_inode;

	tmpfs_file_t *file = tmpfs_create_file(dir, name);

	if(!file)
		return NULL;
	
	file->st_uid = 0;
	file->st_gid = 0;
	file->mode = mode;
	file->rdev = dev;

	struct dev *d = dev_find(dev);

	file->type = TMPFS_FILE_TYPE_CHAR;

	if(d)
	{
		file->type = d->is_block ? TMPFS_FILE_TYPE_BLOCK : TMPFS_FILE_TYPE_CHAR;
		d->file = file;
	}

	struct inode *in = tmpfs_file_to_vfs(file, root);
	if(!in)
		return NULL;
	
	superblock_add_inode(ino->i_sb, in);

	return in;
}

off_t tmpfs_getdirent(struct dirent *buf, off_t off, struct file* file)
{
	struct inode *ino = file->f_ino;
	tmpfs_file_t *dir = (tmpfs_file_t *) ino->i_inode;
	off_t orig_off = off;

	mutex_lock(&dir->dirent_lock);

	tmpfs_file_t *f = dir->child;

	while(off != 0)
	{
		if(!f)
		{
			mutex_unlock(&dir->dirent_lock);
			return 0;
		}
		f = f->sibblings;
		off--;
	}

	if(!f)
	{
		mutex_unlock(&dir->dirent_lock);
		return 0;
	}

	strlcpy(buf->d_name, f->name, 255);
	buf->d_ino = (ino_t) f;
	buf->d_off = orig_off;
	buf->d_reclen = sizeof(struct dirent) - (256 - (strlen(buf->d_name) + 1));

	if(f->type & VFS_TYPE_DIR)
		buf->d_type = DT_DIR;
	else if(f->type & VFS_TYPE_BLOCK_DEVICE)
		buf->d_type = DT_BLK;
	else if(f->type & VFS_TYPE_CHAR_DEVICE)
		buf->d_type = DT_CHR;
	else if(f->type & VFS_TYPE_SYMLINK)
		buf->d_type = DT_LNK;
	else if(f->type & VFS_TYPE_FILE)
		buf->d_type = DT_REG;

	mutex_unlock(&dir->dirent_lock);

	return orig_off + 1;
}

int tmpfs_stat(struct stat *buf, struct file *f)
{
	struct inode *node = f->f_ino;
	tmpfs_file_t *file = (tmpfs_file_t *) node->i_inode;
	buf->st_ino = (ino_t) file;
	buf->st_size = file->size;
	buf->st_mode = file->mode;
	buf->st_gid = file->st_gid;
	buf->st_uid = file->st_uid;
	buf->st_rdev = file->rdev;

	return 0;
}

char *tmpfs_readlink(struct file *f)
{
	tmpfs_file_t *file = (tmpfs_file_t *) f->f_ino->i_inode;

	return strdup(file->symlink);
}

static void tmpfs_set_node_fileops(struct inode *node)
{
	node->i_fops.creat = tmpfs_creat;
	node->i_fops.read = tmpfs_read;
	node->i_fops.write = tmpfs_write;
	node->i_fops.mkdir = tmpfs_mkdir;
	node->i_fops.open = tmpfs_open;
	node->i_fops.symlink = tmpfs_symlink;
	node->i_fops.mknod = tmpfs_mknod;
	node->i_fops.getdirent = tmpfs_getdirent;
	node->i_fops.stat = tmpfs_stat;
	node->i_fops.readpage = tmpfs_readpage;
	node->i_fops.writepage = tmpfs_writepage;
	node->i_fops.readlink = tmpfs_readlink;
}

tmpfs_filesystem_t *__tmpfs_allocate_fs(void)
{
	tmpfs_filesystem_t *new_fs = zalloc(sizeof(tmpfs_filesystem_t));
	if(!new_fs)
		return NULL;

	tmpfs_file_t *new_root = zalloc(sizeof(tmpfs_file_t));
	if(!new_root)
		return NULL;
	
	/* Setup the tmpfs root */
	new_root->name = "";
	new_root->parent = new_root;
	new_root->type = TMPFS_FILE_TYPE_DIR;
	new_fs->root = new_root;

	tmpfs_append(new_fs);
	return new_fs;
}

static void tmpfs_destroy_early(tmpfs_filesystem_t *fs)
{
	if(fs->superblock) free(fs->superblock);
	if(fs->root) free(fs->root);
	free(fs);
}

int tmpfs_mount(const char *mountpoint)
{
	LOG("tmpfs", "Mounting on %s\n", mountpoint);

	tmpfs_filesystem_t *fs = __tmpfs_allocate_fs();

	fs->superblock = zalloc(sizeof(struct superblock));
	if(!fs->superblock)
	{
		tmpfs_destroy_early(fs);
		return -1;
	}

	struct inode *node = inode_create(false);
	if(!node)
	{
		tmpfs_destroy_early(fs);
		return -1;
	}

	node->i_type = VFS_TYPE_DIR;
	node->i_helper = fs;
	node->i_inode = (ino_t) fs->root;
	node->i_sb = fs->superblock;
	node->i_mode = 0755;

	tmpfs_set_node_fileops(node);

	if(mount_fs(node, mountpoint) < 0)
	{
		tmpfs_destroy_early(fs);
		free(node);
		return -1;
	}

	return 0;
}

tmpfs_filesystem_t *tmpfs_get_root(struct file *f)
{
	return f->f_ino->i_helper;
}

tmpfs_file_t *tmpfs_get_raw_file(struct file *f)
{
	return (void *) f->f_ino->i_inode;
}
