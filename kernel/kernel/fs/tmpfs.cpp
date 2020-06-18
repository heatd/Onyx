/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <onyx/dev.h>
#include <onyx/tmpfs.h>
#include <onyx/log.h>
#include <onyx/vfs.h>
#include <onyx/mutex.h>
#include <onyx/page.h>
#include <onyx/dev.h>
#include <onyx/dentry.h>
#include <onyx/atomic.hpp>
#include <onyx/cred.h>

static DECLARE_MUTEX(tmpfs_list_lock);
static struct list_head filesystems = LIST_HEAD_INIT(filesystems);
struct dev *master_tmpfs = nullptr;

atomic<ino_t> tmpfs_superblock::curr_minor_number{1};

tmpfs_inode *tmpfs_create_inode(mode_t mode, struct dentry *dir, dev_t rdev = 0)
{
	auto dir_inode = dir->d_inode;
	auto sb = (tmpfs_superblock *) dir_inode->i_sb;
	return sb->create_inode(mode, rdev);
}

struct inode *tmpfs_creat(const char *name, int mode, struct dentry *dir)
{
	return tmpfs_create_inode(static_cast<mode_t>(S_IFREG | mode), dir);
}

int tmpfs_link(struct file *target_ino, const char *name, struct dentry *dir)
{
	return 0;
}

inode *tmpfs_symlink(const char *name, const char *dest, struct dentry *dir)
{
	const char *link_name = strdup(dest);
	if(!link_name)
		return nullptr;
	
	auto new_ino = tmpfs_create_inode(S_IFLNK | 0777, dir);
	if(!new_ino)
	{
		free((void *) link_name);
		return nullptr;
	}

	new_ino->link = link_name;

	return new_ino;
}

inode *tmpfs_mkdir(const char *name, mode_t mode, struct dentry *dir)
{
	return tmpfs_create_inode(mode | S_IFDIR, dir);
}

inode *tmpfs_mknod(const char *name, mode_t mode, dev_t dev, struct dentry *dir)
{
	return tmpfs_create_inode(mode, dir, dev);
}

char *tmpfs_readlink(struct file *f)
{
	tmpfs_inode *ino = static_cast<tmpfs_inode *>(f->f_ino);

	return strdup(ino->link);
}

int tmpfs_unlink(const char *name, int flags, struct dentry *dir)
{
	return 0;
}

ssize_t tmpfs_readpage(struct page *page, size_t offset, struct inode *ino)
{
	return -EIO;
}

ssize_t tmpfs_writepage(struct page *page, size_t offset, struct inode *ino)
{
	return PAGE_SIZE;
}

struct inode *tmpfs_open(struct dentry *dir, const char *name)
{
	/* This a no-op, since names are either cached or non-existant in our tmpfs */
	return errno = ENOENT, nullptr;
}

void put_dentry_to_dirent(struct dirent *buf, dentry *dentry, const char *special_name = nullptr)
{
	auto ino = dentry->d_inode;

	const char *name = special_name ?: dentry->d_name;

	buf->d_ino = ino->i_inode;
	auto len = strlen(name);
	memcpy(buf->d_name, name, len);
	buf->d_name[len] = '\0';
	buf->d_reclen = sizeof(dirent) - (256 - (len + 1));
	
	if(S_ISDIR(ino->i_mode))
		buf->d_type = DT_DIR;
	else if(S_ISBLK(ino->i_mode))
		buf->d_type = DT_BLK;
	else if(S_ISCHR(ino->i_mode))
		buf->d_type = DT_CHR;
	else if(S_ISLNK(ino->i_mode))
		buf->d_type = DT_LNK;
	else if(S_ISREG(ino->i_mode))
		buf->d_type = DT_REG;
	else if(S_ISSOCK(ino->i_mode))
		buf->d_type = DT_SOCK;
	else if(S_ISFIFO(ino->i_mode))
		buf->d_type = DT_FIFO;
	else
		buf->d_type = DT_UNKNOWN;

}

off_t tmpfs_getdirent(struct dirent *buf, off_t off, struct file *file)
{
	auto dent = file->f_dentry;
	
	buf->d_off = off;

	if(off == 0)
	{
		/* . */
		put_dentry_to_dirent(buf, dent, ".");
	}
	else if(off == 1)
	{
		/* .. */
		auto parent = dentry_parent(dent);
		put_dentry_to_dirent(buf, parent, "..");
		dentry_put(parent);
	}
	else
	{
		scoped_rwlock<rw_lock::read> g(dent->d_lock);

		off_t c = 0;
		list_for_every(&dent->d_children_head)
		{
			if((c++) - 2 != off)
				continue;
			
			auto d = container_of(l, dentry, d_parent_dir_node);
			put_dentry_to_dirent(buf, d);
			return off + 1;
		}

		return 0;
	}

	return off + 1;
}

struct file_ops tmpfs_fops = 
{
	.read = nullptr,
	.write = nullptr,
	.open = tmpfs_open,
	.close = nullptr,
	.getdirent = tmpfs_getdirent,
	.ioctl = nullptr,
	.creat = tmpfs_creat,
	.stat = nullptr,
	.link = tmpfs_link,
	.symlink = tmpfs_symlink,
	.mmap = nullptr,
	.ftruncate = nullptr,
	.mkdir = tmpfs_mkdir,
	.mknod = tmpfs_mknod,
	.on_open = nullptr,
	.poll = nullptr,
	.readlink = tmpfs_readlink,
	.unlink = tmpfs_unlink,
	.fallocate = nullptr,
	.readpage = tmpfs_readpage,
	.writepage = tmpfs_writepage
};

tmpfs_inode *tmpfs_superblock::create_inode(mode_t mode, dev_t rdev)
{
	tmpfs_inode *ino = new tmpfs_inode();
	if(!ino)
		return ino;

	if(ino->init(mode) < 0)
	{
		delete ino;
		return nullptr;
	}
	
	ino->i_fops = &tmpfs_fops;

	ino->i_nlink = 1;

	inode_ref(ino);

	/* We're currently holding two refs: one for the user, and another for the simple fact
	 * that we need this inode to remain in memory.
	 */

	superblock_add_inode(this, ino);

	/* Now, refcount should equal 3, because the inode cache just grabbed it... */

	auto c = creds_get();

	ino->i_mode = mode;
	ino->i_ctime = ino->i_atime = ino->i_mtime = clock_get_posix_time();
	ino->i_dev = s_devnr;
	ino->i_inode = curr_inode.fetch_add(1);
	ino->i_gid = c->egid;
	ino->i_uid = c->euid;
	creds_put(c);

	ino->i_rdev = rdev;
	ino->i_type = mode_to_vfs_type(mode);
	ino->i_sb = this;
	ino->i_rdev = rdev;
	ino->i_blocks = 0;

	if(inode_is_special(ino))
	{
		int st = inode_special_init(ino);
		if(st < 0)
		{
			errno = -st;
			/* TODO: Cleanup */
			return nullptr;
		}
	}

	return ino;
}

static void tmpfs_append(tmpfs_superblock *fs)
{
	mutex_lock(&tmpfs_list_lock);

	list_add_tail(&fs->fs_list_node, &filesystems);

	mutex_unlock(&tmpfs_list_lock);
}

tmpfs_superblock *tmpfs_create_sb(void)
{
	tmpfs_superblock *new_fs = new tmpfs_superblock{};
	if(!new_fs)
		return NULL;

	superblock_init(new_fs);

	tmpfs_append(new_fs);
	return new_fs;
}

int tmpfs_mount(const char *mountpoint)
{
	LOG("tmpfs", "Mounting on %s\n", mountpoint);

	auto new_sb = tmpfs_create_sb();
	if(!new_sb)
		return -ENOMEM;

	char name[NAME_MAX + 1];
	snprintf(name, NAME_MAX, "tmpfs-%lu", new_sb->fs_minor);

	auto minor = MINOR(master_tmpfs->majorminor) + new_sb->fs_minor;

	auto new_dev = dev_register(MAJOR(master_tmpfs->majorminor), minor, name);
	if(!new_dev)
	{
		delete new_sb;
		return -ENOMEM;
	}

	new_sb->s_devnr = new_dev->majorminor;
	
	auto node = new_sb->create_inode(S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if(!node)
	{
		dev_unregister(new_sb->s_devnr);
		delete new_sb;
		return -ENOMEM;
	}

	if(mount_fs(node, mountpoint) < 0)
	{
		dev_unregister(new_sb->s_devnr);
		superblock_kill(new_sb);
		delete new_sb;
		/* We need to unref the inode two times, one for our ref
		 * and another one for the persistence. */
		close_vfs(node);
		close_vfs(node);
		return -errno;
	}

	return 0;
}

__init void tmpfs_init()
{
	/* We need to allocate a range of devices for tmpfs usage*/
	master_tmpfs = dev_register(0, 0, "tmpfs");
	assert(master_tmpfs != nullptr);
}
