/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <errno.h>

#include <onyx/dentry.h>
#include <onyx/compiler.h>
#include <onyx/slab.h>
#include <onyx/atomic.h>
#include <onyx/vfs.h>
#include <onyx/file.h>
#include <onyx/mm/pool.hpp>
#include <onyx/mtable.h>

static memory_pool<dentry, true> dentry_pool;
dentry *root_dentry = nullptr;

extern "C"
{

void dentry_get(dentry *d)
{
	/* Must hold parent's d_lock */
	__atomic_add_fetch(&d->d_ref, 1, __ATOMIC_RELAXED);
}

void dentry_destroy(dentry *d);

void dentry_put(dentry *d)
{
	if(__atomic_sub_fetch(&d->d_ref, 1, __ATOMIC_RELAXED) == 0)
		dentry_destroy(d);
}

void dentry_destroy(dentry *d)
{
	close_vfs(d->d_inode);
	dentry_put(d->d_parent);
}

dentry *dentry_create(const char *name, inode *inode, dentry *parent)
{
	dentry *new_dentry = dentry_pool.allocate();
	if(!new_dentry) [[unlikely]]
		return nullptr;
	memset(new_dentry, 0, sizeof(dentry));

	new_dentry->d_ref = 1;
	new_dentry->d_name = new_dentry->d_inline_name;
	
	size_t name_length = strlen(name);

	if(name_length <= INLINE_NAME_MAX)
	{
		strlcpy(new_dentry->d_name, name, INLINE_NAME_MAX);
	}
	else
	{
		char *dname = (char *) memdup((void *) name, name_length);
		if(!dname)
		{
			dentry_pool.free(new_dentry);
			return nullptr;
		}

		new_dentry->d_name = dname;
	}

	new_dentry->d_name_length = name_length;
	new_dentry->d_name_hash = fnv_hash(new_dentry->d_name, new_dentry->d_name_length);
	new_dentry->d_inode = inode;
	object_ref(&inode->i_object);
	new_dentry->d_parent = parent; 
	
	if(parent) [[likely]]
	{
		rw_lock_write(&parent->d_lock);
		list_add_tail(&new_dentry->d_parent_dir_node, &parent->d_children_head);
		rw_unlock_write(&parent->d_lock);
		dentry_get(parent);
	}

	INIT_LIST_HEAD(&new_dentry->d_children_head);

	return new_dentry;
}

dentry *dentry_try_to_open(const char *name, dentry *dir)
{
	struct file f;
	f.f_ino = dir->d_inode;
	printk("trying to open %s\n", name);
	inode *ino = dir->d_inode->i_fops->open(&f, name);
	if(!ino)
	{
		printk("failed\n");
		return nullptr;
	}

	rw_lock_write(&dir->d_lock);

	auto ret = dentry_create(name, ino, dir);
	close_vfs(ino);

	if(ret)
		dentry_get(ret);

	rw_unlock_write(&dir->d_lock);

	return ret;
}

dentry *dentry_parent(dentry *dir)
{
	rw_lock_read(&dir->d_lock);
	assert(dir->d_inode->i_type == VFS_TYPE_DIR);

	auto ret = dir->d_parent;
	dentry_get(ret);
	rw_unlock_read(&dir->d_lock);
	return ret;
}

dentry *dentry_lookup_internal(const char *name, dentry *dir)
{
	fnv_hash_t hash = fnv_hash(name, strlen(name));

	if(!strcmp(name, "."))
		return dir;

	rw_lock_read(&dir->d_lock);

	if(!strcmp(name, ".."))
	{
		auto ret = dir->d_parent;
		dentry_get(ret);
		rw_unlock_read(&dir->d_lock);
		return ret;
	}

	list_for_every(&dir->d_children_head)
	{
		dentry *d = container_of(l, dentry, d_parent_dir_node);
		if(d->d_name_hash == hash)
		{
			dentry_get(d);
			rw_unlock_read(&dir->d_lock);
			return d;
		}
	}

	rw_unlock_read(&dir->d_lock);
	return dentry_try_to_open(name, dir);
}

dentry *dentry_open(char *path, struct dentry *base)
{
	char *saveptr;

	/* Now, tokenize it using strtok */
	path = strtok_r(path, "/", &saveptr);
	dentry *node = base;

	/* We'll use this lambda to put the dentry when error'ing - that's why we
	 * don't need to check for to_be_put == new_found. */
	auto conditional_put = [base](dentry *to_be_put)
	{
		if(to_be_put != base)
			dentry_put(to_be_put);
	};

	while(path)
	{
		auto new_found = dentry_lookup_internal(path, node);
		if(!new_found)
		{
			conditional_put(node);
			return nullptr;
		}
	
		if(new_found->d_inode->i_type == VFS_TYPE_SYMLINK)
		{
			file f;
			f.f_ino = new_found->d_inode;

			auto target_str = readlink_vfs(&f);
			if(!target_str)
			{
				conditional_put(node);
				conditional_put(new_found);
				return nullptr;
			}

			conditional_put(new_found);
		
			auto symlink_target = dentry_open(target_str, node);
			if(!symlink_target)
			{
				conditional_put(node);
				return nullptr;
			}

			new_found = symlink_target;
		}

		/* Only valid if we start backtracking(open ..) or we open . or whatever */
		if(node != base && node != new_found) [[unlikely]]
			dentry_put(node);

		node = new_found;

		path = strtok_r(NULL, "/", &saveptr);	
	}

	return node;
}

dentry *dentry_mount(const char *mountpoint, struct inode *inode)
{
	if(!strcmp(mountpoint, "/")) [[unlikely]]
	{
		/* shortpath: We're creating the absolute root inode */
		return (root_dentry = dentry_create(mountpoint, inode, nullptr));
	}

	char *path = strdup(mountpoint);
	if(!path)
		return nullptr;
	
	dentry *base_dentry = dentry_open(path, root_dentry);
	if(!base_dentry)
	{
		free((void *) path);
		return nullptr;
	}

	strcpy(path, mountpoint);

	dentry *new_d = dentry_create(basename(path), inode, base_dentry);

	if(new_d)
	{
		rw_lock_write(&base_dentry->d_lock);
		if(base_dentry->d_flags & DENTRY_FLAG_MOUNTPOINT)
		{
			rw_unlock_write(&base_dentry->d_lock);
			return errno = EBUSY, nullptr;
		}

		base_dentry->d_mount_dentry = new_d;
		dentry_get(new_d);

		rw_unlock_write(&base_dentry->d_lock);
	}

	free((void *) path);
	dentry_put(base_dentry);

	return new_d;
}

struct file *do_actual_open(struct file *basef, const char *name)
{
	assert(basef != NULL);

	if(basef->f_ino->i_fops->open == NULL)
		return errno = EIO, nullptr;

	struct inode *i = basef->f_ino->i_fops->open(basef, name);

	if(!i)
		return NULL;
	
	struct file *f = inode_to_file(i);
	if(!f)
	{
		close_vfs(i);
		return NULL;
	}

	if(f->f_ino->i_fops->on_open)
	{
		if(f->f_ino->i_fops->on_open(f) < 0)
		{
			fd_put(f);
			return NULL;
		}		
	}

	return f;
}

int mount_fs(struct inode *fsroot, const char *path)
{
	assert(fsroot != NULL);

	printk("mount_fs: Mounting on %s\n", path);
	
	if(!strcmp(path, "/"))
	{
		file *f = (file *) zalloc(sizeof(*f));
		if(!f)
			return -ENOMEM;
		f->f_ino = fsroot;
		f->f_refcount = 1;
		f->f_dentry = dentry_mount("/", fsroot);
		assert(f->f_dentry != nullptr);

		auto fs_root = get_filesystem_root();
		if(fs_root->file)
		{
			fd_put(fs_root->file);
		}

		fs_root->file = f;	
	}
	else
	{
		/* TODO: This seems iffy logic, at best */
		/* FIXME: This code's all broken. const casts, etc... */
		dentry_mount(path, fsroot);
		struct file *file = open_vfs(get_fs_root(), dirname((char*) path));
		if(!file)
			return -errno;

		file = do_actual_open(file, basename((char*) path));
		if(!file)
			return -errno;

		struct file *fsroot_f = inode_to_file(fsroot);
		if(!fsroot_f)
		{
			fd_put(file);
			return -ENOMEM;
		}
	
		return mtable_mount(file, fsroot_f);
	}

	return 0;
}

struct nameidata
{
	dentry *root;
	const char *whole_path;
	const char *path_element;
	dentry *location;
};

dentry *dentry_resolve(nameidata& data)
{
	printk("Path: %s\n", data.whole_path);
	return nullptr;
}

struct file *open_vfs(struct file *f, const char *name)
{
	nameidata namedata;
	namedata.root = root_dentry;
	namedata.whole_path = name;
	namedata.location = f->f_dentry;
	dentry_resolve(namedata);

	/* open(3): empty strings require us to return ENOENT */
	if(strlen(name) == 0)
		return errno = ENOENT, nullptr;
	/* Okay, so we need to traverse the path */
	/* First off, dupe the string */
	char *path = strdup(name);
	if(!path)
		return errno = ENOMEM, nullptr;

	auto dent = dentry_open(path, f->f_dentry);
	
	free((void *) path);

	if(!dent)
		return nullptr;

	auto new_file = inode_to_file(f->f_ino);
	if(!new_file)
	{
		dentry_put(dent);
		return nullptr;
	}
	
	new_file->f_dentry = dent;

	return new_file;
}

void dentry_init(void) {}

};
