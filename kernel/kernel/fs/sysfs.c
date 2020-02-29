/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <onyx/panic.h>
#include <onyx/dev.h>
#include <onyx/sysfs.h>
#include <onyx/vfs.h>

struct sysfs_file sysfs_root = {0};
struct inode *sysfs_root_ino = NULL;

void sysfs_setup_fops(struct inode *ino);
struct sysfs_file *sysfs_create_dir(const char *name, int perm, struct inode *ino);

struct sysfs_file *lookup_in_sysfs_dirent(struct sysfs_file *file, char *segm)
{
	struct sysfs_file *f = file->children;
	while(f)
	{
		if(!strcmp(f->name, segm))
			return f;
		f = f->next;
	}
	return NULL;
}

struct inode *sysfs_create_inode_for_file(struct sysfs_file *f)
{
	struct inode *ino = inode_create();
	if(!ino)
		return NULL;

	ino->i_type = f->type;
	ino->i_mode = f->perms;
	ino->i_sb = sysfs_root_ino->i_sb;
	ino->i_dev = sysfs_root_ino->i_dev;
	ino->i_inode = (ino_t) f;
	
	sysfs_setup_fops(ino);
	
	return ino;
}

struct sysfs_file *sysfs_create_file(char *name)
{
	struct sysfs_file *file = malloc(sizeof(struct sysfs_file));
	if(!file)
	{
		errno = ENOMEM;
		goto error;
	}
	file->type = VFS_TYPE_FILE;
	file->inode = (ino_t) file;
	file->children = NULL;
	file->next = NULL;
	file->name = strdup(name);
	if(!file->name)
	{
		errno = ENOMEM;
		goto error;
	}

	return file;
error:
	if(file)	free(file->name);
	free(file);
	return NULL;
}

void sysfs_add(struct sysfs_file *dir, struct sysfs_file *f)
{
	if(!dir->children)
		dir->children = f;
	else
	{
		struct sysfs_file *__f = dir->children;
		while(__f->next) __f = __f->next;
		__f->next = f;
	}
}

struct inode *sysfs_creat(const char *pathname, int mode, struct inode *node)
{
	struct sysfs_file *file;
	struct sysfs_file *f = NULL;

	file = (struct sysfs_file*) node->i_inode;

	f = sysfs_create_file((char *) pathname);
	if(!f)
		goto error;

	f->perms = mode;
	sysfs_add(file, f);

	struct inode *ino = sysfs_create_inode_for_file(f);
	return ino;
error:
	if(f) 		free(f->name);
	free(f);
	return NULL;
}

struct sysfs_file *sysfs_create_entry(const char *pathname, int mode, struct inode *node)
{
	char *path = NULL;
	char *segm;
	char *saveptr;
	char *next_segm;
	struct sysfs_file *file;
	struct sysfs_file *f = NULL;

	path = strdup(pathname);
	if(!path) return errno = ENOMEM, NULL;
	segm = strtok_r(path, "/", &saveptr);
	file = (struct sysfs_file*) node->i_inode;
	if(!file)
	{
		errno = EBADFD;
		goto error;
	}

	while(segm)
	{
		next_segm = strtok_r(NULL, "/", &saveptr);
		if(next_segm)
		{
			file = lookup_in_sysfs_dirent(file, segm);
			if(!file)
				goto error;
		}
		else
			break;	
		segm = next_segm;
	}
	f = sysfs_create_file(segm);
	if(!f)
		goto error;

	f->perms = mode;

	free(path);

	sysfs_add(file, f);
	return f;
error:
	free(path);
	if(f) 		free(f->name);
	free(f);
	return NULL;
}

struct inode *sysfs_open(struct inode *node, const char *name)
{
	char *segm;
	char *saveptr;
	char *path = strdup(name);
	if(!path)
		return NULL;
	struct sysfs_file *file = (struct sysfs_file*) node->i_inode;
	if(!file)
		return NULL; /* This should never happen, maybe in corruption? */
	if(!(node->i_type & VFS_TYPE_DIR))
		return errno = ENOTDIR, NULL;
	segm = strtok_r(path, "/", &saveptr);
	 
	/* Iterate through the path */
	while(segm)
	{
		file = lookup_in_sysfs_dirent(file, segm);
		if(!file)
		{
			free(path);
			return errno = ENOENT, NULL;
		}
		segm = strtok_r(NULL, "/", &saveptr);
	}

	free(path);

	struct inode *ino = sysfs_create_inode_for_file(file);

	if(ino)
	{
		superblock_add_inode(node->i_sb, ino);
	}

	return ino;
}

size_t sysfs_read(int flags, size_t offset, size_t sizeofread, void *buffer, struct inode *this)
{
	struct sysfs_file *file = (struct sysfs_file*) this->i_inode;
	assert(file != NULL);

	if(file->read) return file->read(buffer, sizeofread, offset);
	else
		return errno = ENOSYS, (size_t) -1;
}

size_t sysfs_write(size_t offset, size_t sizeofwrite, void *buffer, struct inode *this)
{
	struct sysfs_file *file = (struct sysfs_file*) this->i_inode;
	assert(file != NULL);

	if(file->write) return file->write(buffer, sizeofwrite, offset);
	else
		return errno = ENOSYS, (size_t) -1;
}

void sysfs_init(void)
{
	/* If this function fails, just panic. sysfs is crucial */
	struct inode *root = inode_create();
	assert(root != NULL);

	struct superblock *sb = zalloc(sizeof(*sb));

	assert(sb != NULL);

	sb->s_ref = 1;

	root->i_sb = sb;
	root->i_type = VFS_TYPE_DIR;
	root->i_inode = (ino_t) &sysfs_root;
	
	sysfs_root.name = "";
	sysfs_root.perms = 0555 | S_IFDIR;
	sysfs_root.type = VFS_TYPE_DIR;
	sysfs_root.inode = root->i_inode;

	sysfs_root_ino = root;
	struct dev *minor = dev_register(0, 0, "sysfs");
	
	assert(minor != NULL);

	root->i_dev = minor->majorminor;
	sysfs_setup_fops(root);
	
	if(mount_fs(root, "/sys") < 0)
		panic("sysfs_init: Could not mount /sys\n");
	
	/* Spawn the standard sysfs directories */
	dev_create_sysfs();
}

void sysfs_mount(void)
{
	if(sysfs_root_ino)
	{
		if(mount_fs(sysfs_root_ino, "/sys") < 0)
			panic("sysfs_mount: Could not mount /sys\n");
	}
}

off_t sysfs_getdirent(struct dirent *buf, off_t off, struct inode *ino)
{
	struct sysfs_file *file = (struct sysfs_file*) ino->i_inode;
	assert(file != NULL);

	struct sysfs_file *f = file->children;

	for(off_t i = 0; i < off; i++)
	{
		if(!f)
			return 0;
		f = f->next;
	}

	if(!f)
		return 0;

	strncpy(buf->d_name, f->name, 256);
	buf->d_ino = f->inode;
	buf->d_off = off;
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

	return off + 1;
}

struct sysfs_file *sysfs_create_dir(const char *name, int perm, struct inode *ino)
{
	struct sysfs_file *f = sysfs_create_entry(name, perm, ino);
	if(!f)
		return NULL;
	f->type = VFS_TYPE_DIR;
	f->perms |= S_IFDIR;
	return f;
}

struct sysfs_file *sysfs_add_device(struct device *dev)
{
	struct inode *inode = open_vfs(sysfs_root_ino, "devices");
	if(!inode)
		return NULL;
	/* Allocate enough space for a busname-devicename\0 */
	char *name = zalloc(strlen(dev->bus->name) + 2 + strlen(dev->name));
	if(!name)
		return NULL;
	sprintf(name, "%s-%s", dev->bus->name, dev->name);
	struct sysfs_file *i = sysfs_create_entry(name, 0666, inode);
	if(!i)
		return NULL;
	i->priv = dev;
	free(name);

	return i;
}

struct sysfs_file *sysfs_add_bus(struct bus *bus)
{
	struct inode *inode = open_vfs(sysfs_root_ino, "bus");
	if(!inode)
		return NULL;
	struct sysfs_file *i = sysfs_create_entry(bus->name, 0666, inode);
	if(!i)
		return NULL;

	i->priv = bus;

	return i;
}

int sysfs_stat(struct stat *buf, struct inode *node)
{
	memset(buf, 0, sizeof(struct stat));

	struct sysfs_file *file = (struct sysfs_file *) node->i_inode;
	buf->st_mode = file->perms;

	buf->st_ino = node->i_inode;
	buf->st_dev = node->i_dev;

	return 0;
}

void sysfs_setup_fops(struct inode *ino)
{
	ino->i_fops.open = sysfs_open;
	ino->i_fops.creat = sysfs_creat;
	ino->i_fops.read = sysfs_read;
	ino->i_fops.write = sysfs_write;
	ino->i_fops.getdirent = sysfs_getdirent;
	ino->i_fops.stat = sysfs_stat;
}
