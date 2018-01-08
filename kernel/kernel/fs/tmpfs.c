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

static mutex_t tmpfs_list_lock;
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

int tmpfs_symlink(const char *dest, struct inode *inode)
{
	tmpfs_file_t *file = (tmpfs_file_t *) inode->inode;

	char *str = strdup(dest);
	if(!str)
		return -1;
	file->symlink = (const char *) str;
	file->type = TMPFS_FILE_TYPE_SYM;
	inode->type = VFS_TYPE_SYMLINK;

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

static tmpfs_file_t *tmpfs_create_file(tmpfs_file_t *dir, const char *name)
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

static struct inode *tmpfs_file_to_vfs(tmpfs_file_t *file, struct inode *parent)
{
	struct inode *f = zalloc(sizeof(struct inode));
	if(!f)
		return NULL;
	switch(file->type)
	{
		case TMPFS_FILE_TYPE_DIR:
			f->type = VFS_TYPE_DIR;
			break;
		case TMPFS_FILE_TYPE_REG:
			f->type = VFS_TYPE_FILE;
			break;
		case TMPFS_FILE_TYPE_SYM:
			f->type = VFS_TYPE_SYMLINK;
			break;
	}

	//f->mode = mode;
	f->uid = file->st_uid;
	f->gid = file->st_gid;
	f->name = vfs_get_full_path(parent, (char*) file->name);
	if(!f->name)
		goto error;
	tmpfs_set_node_fileops(f);
	f->inode = (ino_t) file;
	f->refcount = 1;
	f->size = file->size;

	return f;
error:
	free(f);
	return NULL;
}

struct inode *tmpfs_creat(const char *pathname, int mode, struct inode *vnode)
{
	tmpfs_file_t *file = (tmpfs_file_t *) vnode->inode;

	assert(file != NULL);

	tmpfs_file_t *new_file = tmpfs_create_file(file, pathname);
	if(!new_file)
		return NULL;

	new_file->mode = mode;
	new_file->type = TMPFS_FILE_TYPE_REG;

	return tmpfs_file_to_vfs(new_file, vnode);
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

size_t tmpfs_read(int flags, size_t offset, size_t size, void *buffer, struct inode *vnode)
{
	tmpfs_file_t *file = (tmpfs_file_t *) vnode->inode;

	char *scratch = __alloc_page(0);
	if(!scratch)
		return errno = ENOMEM, (size_t) -1;
	scratch = PHYS_TO_VIRT(scratch);
	ssize_t read = 0;
	while(read != (ssize_t) size)
	{
		size_t block = offset / block_size;
		off_t block_off = offset % block_size;
		off_t block_left = block_size - block_off;
		if(!tmpfs_read_block(file, block, scratch))
			return read;
		size_t amount = (ssize_t) (size - read) < block_left ? (ssize_t) size - read : block_left;
		if(offset + amount > vnode->size)
		{
			amount = vnode->size - offset;
			memcpy(buffer + read, scratch + block_off, amount);
			read += amount;
			return read;
		}
		else
			memcpy(buffer + read, scratch + block_off, amount);
		read += amount;
		offset += amount;
	}
	__free_page(scratch - PHYS_BASE);
	return read;
}

size_t tmpfs_write(size_t offset, size_t size, void *buffer, struct inode *vnode)
{
	/* We don't write anything since it should be cached anyway */
	return size;
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
	memcpy(&block->data, buf, size);
	return 0;
}

int tmpfs_fill_with_data(struct inode *vnode, const void *_buf, size_t size)
{
	tmpfs_file_t *file = (tmpfs_file_t *) vnode->inode;
	
	const char *buf = _buf;
	size_t nr_reads = vmm_align_size_to_pages(size);
	off_t off = 0;

	for(size_t i = 0; i < nr_reads; i++)
	{
		size_t sz = size - off < block_size ? size - off : block_size; 
		if(tmpfs_add_block(buf, sz, file) < 0)
			return errno = ENOSPC, -1;
		file->size += sz;
		vnode->size += sz;
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

struct inode *tmpfs_mkdir(const char *name, mode_t mode, struct inode *vnode)
{
	tmpfs_file_t *file = (tmpfs_file_t *) vnode->inode;
	
	assert(file != NULL);
	
	if(tmpfs_open_file(file, name))
		return errno = EEXIST, NULL;

	tmpfs_file_t *new_file = tmpfs_create_file(file, name);
	if(!new_file)
		return NULL;

	new_file->mode = mode;
	new_file->type = TMPFS_FILE_TYPE_DIR;
	
	return tmpfs_file_to_vfs(new_file, vnode);
}

struct inode *tmpfs_open(struct inode *vnode, const char *name)
{
	tmpfs_file_t *dir = (tmpfs_file_t *) vnode->inode;
	
	assert(dir != NULL);

	tmpfs_file_t *file = tmpfs_open_file(dir, name);
	if(!file)
		return NULL;

	if(file->type == TMPFS_FILE_TYPE_SYM)
	{
		return open_vfs(*file->symlink == '/' ? fs_root : vnode, file->symlink);
	}

	return tmpfs_file_to_vfs(file, vnode);
}

static void tmpfs_set_node_fileops(struct inode *node)
{
	node->fops.creat = tmpfs_creat;
	node->fops.read = tmpfs_read;
	node->fops.write = tmpfs_write;
	node->fops.mkdir = tmpfs_mkdir;
	node->fops.open = tmpfs_open;
	node->fops.symlink = tmpfs_symlink;
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

int tmpfs_mount(const char *mountpoint)
{
	LOG("tmpfs", "Mounting on %s\n", mountpoint);

	tmpfs_filesystem_t *fs = __tmpfs_allocate_fs();

	struct inode *node = malloc(sizeof(struct inode));
	if(!node)
		return -1;
	memset(node, 0, sizeof(struct inode));

	node->name = "";
	node->mountpoint = (char*) mountpoint;
	node->type = VFS_TYPE_DIR;
	node->helper = fs;
	node->inode = (ino_t) fs->root;

	tmpfs_set_node_fileops(node);

	mount_fs(node, mountpoint);
	return 0;
}
