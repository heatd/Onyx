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

struct sysfs_object sysfs_root =
{
	.name = "",
	.inode = (ino_t) &sysfs_root,
	.perms = 0644 | S_IFDIR,
	.dentries = LIST_HEAD_INIT(sysfs_root.dentries)
};

struct inode *sysfs_root_ino = NULL;

void sysfs_setup_fops(struct inode *ino);

int sysfs_type_to_vfs_type(mode_t mode)
{
	if(S_ISDIR(mode))
		return VFS_TYPE_DIR;
	else if(S_ISREG(mode))
		return VFS_TYPE_FILE;
	else if(S_ISBLK(mode))
		return VFS_TYPE_BLOCK_DEVICE;
	else if(S_ISCHR(mode))
		return VFS_TYPE_CHAR_DEVICE;
	else if(S_ISLNK(mode))
		return VFS_TYPE_SYMLINK;
	else if(S_ISFIFO(mode))
		return VFS_TYPE_FIFO;
	else if(S_ISSOCK(mode))
		return VFS_TYPE_UNIX_SOCK;

	return VFS_TYPE_UNK;
}

struct inode *sysfs_create_inode_for_file(struct sysfs_object *f)
{
	struct inode *ino = inode_create(false);
	if(!ino)
		return NULL;

	ino->i_type = sysfs_type_to_vfs_type(f->perms);
	ino->i_mode = f->perms;
	ino->i_sb = sysfs_root_ino->i_sb;
	ino->i_dev = sysfs_root_ino->i_dev;
	ino->i_inode = (ino_t) f;
	ino->i_flags = INODE_FLAG_DONT_CACHE;

	sysfs_setup_fops(ino);
	
	return ino;
}

struct inode *sysfs_creat(const char *pathname, int mode, struct inode *node)
{
	return errno = EPERM, NULL;
}

/* Note: Returns with a reference to the return obj if !NULL */
struct sysfs_object *sysfs_get_obj(struct sysfs_object *file, const char *name)
{
	spin_lock(&file->dentry_lock);

	list_for_every(&file->dentries)
	{
		struct sysfs_object *obj = container_of(l, struct sysfs_object, dentry_node);

		if(!strcmp(obj->name, name))
		{
			object_ref(&obj->obj);
			spin_unlock(&file->dentry_lock);
			return obj;
		}
	}

	spin_unlock(&file->dentry_lock);

	return NULL;
}

struct inode *sysfs_open(struct inode *node, const char *name)
{

	struct sysfs_object *file = (struct sysfs_object*) node->i_inode;
	assert(file != NULL);

	if(!(node->i_type & VFS_TYPE_DIR))
		return errno = ENOTDIR, NULL;

	struct sysfs_object *o = sysfs_get_obj(file, name);

	if(!o)
	{
		return errno = ENOENT, NULL;
	}

	struct inode *ino = sysfs_create_inode_for_file(o);

	if(ino)
	{
		superblock_add_inode(node->i_sb, ino);
	}
	else
	{
		object_unref(&o->obj);
	}

	return ino;
}

size_t sysfs_read(int flags, size_t offset, size_t sizeofread, void *buffer, struct inode *this)
{
	struct sysfs_object *file = (struct sysfs_object*) this->i_inode;
	assert(file != NULL);

	if(file->read) return file->read(buffer, sizeofread, offset);
	else
		return errno = ENOSYS, (size_t) -1;
}

size_t sysfs_write(size_t offset, size_t sizeofwrite, void *buffer, struct inode *this)
{
	struct sysfs_object *file = (struct sysfs_object*) this->i_inode;
	assert(file != NULL);

	if(file->write) return file->write(buffer, sizeofwrite, offset);
	else
		return errno = ENOSYS, (size_t) -1;
}

void sysfs_init(void)
{
	/* If this function fails, just panic. sysfs is crucial */
	struct inode *root = inode_create(false);
	assert(root != NULL);

	struct superblock *sb = zalloc(sizeof(*sb));

	assert(sb != NULL);

	sb->s_ref = 1;

	root->i_sb = sb;
	root->i_inode = (ino_t) &sysfs_root;

	root->i_type = sysfs_type_to_vfs_type(sysfs_root.perms);

	sysfs_root_ino = root;
	struct dev *minor = dev_register(0, 0, "sysfs");
	
	assert(minor != NULL);

	root->i_dev = minor->majorminor;
	sysfs_setup_fops(root);
	
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
	struct sysfs_object *file = (struct sysfs_object*) ino->i_inode;
	assert(file != NULL);

	spin_lock(&file->dentry_lock);

	struct sysfs_object *f = NULL;
	off_t advanced = 0;

	list_for_every(&file->dentries)
	{
		if(advanced++ == off)
		{
			f = container_of(l, struct sysfs_object, dentry_node);
			object_ref(&f->obj);
		}
	}

	spin_unlock(&file->dentry_lock);

	if(!f)
		return 0;

	strncpy(buf->d_name, f->name, 256);
	buf->d_ino = f->inode;
	buf->d_off = off;
	buf->d_reclen = sizeof(struct dirent) - (256 - (strlen(buf->d_name) + 1));

	if(S_ISDIR(f->perms))
		buf->d_type = DT_DIR;
	else if(S_ISBLK(f->perms))
		buf->d_type = DT_BLK;
	else if(S_ISCHR(f->perms))
		buf->d_type = DT_CHR;
	else if(S_ISLNK(f->perms))
		buf->d_type = DT_LNK;
	else if(S_ISREG(f->perms))
		buf->d_type = DT_REG;
	else
		buf->d_type = DT_UNKNOWN;

	object_unref(&f->obj);

	return off + 1;
}

int sysfs_stat(struct stat *buf, struct inode *node)
{
	memset(buf, 0, sizeof(struct stat));

	struct sysfs_object *file = (struct sysfs_object *) node->i_inode;
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


void sysfs_release(struct object *obj)
{}

int sysfs_object_init(const char *name, struct sysfs_object *obj)
{
	char *namedup = strdup(name);
	if(!namedup)
		return -ENOMEM;

	memset(obj, 0, sizeof(*obj));
	
	object_init(&obj->obj, sysfs_release);

	obj->name = namedup;

	/* TODO: Init obj->inode properly, without address leaks */
	obj->inode = (ino_t) obj;

	INIT_LIST_HEAD(&obj->dentries);

	return 0;
}

static void __sysfs_append(struct sysfs_object *obj, struct sysfs_object *parent)
{
	spin_lock(&parent->dentry_lock);

	list_add_tail(&obj->dentry_node, &parent->dentries);

	spin_unlock(&parent->dentry_lock);
}

void sysfs_add(struct sysfs_object *obj, struct sysfs_object *parent)
{
	if(!parent)
		parent = &sysfs_root;
	
	obj->parent = parent;

	__sysfs_append(obj, parent);
}

int sysfs_init_and_add(const char *name, struct sysfs_object *obj, struct sysfs_object *parent)
{
	int st = sysfs_object_init(name, obj);

	if(st < 0)
		return st;
	
	sysfs_add(obj, parent);

	return 0;
}