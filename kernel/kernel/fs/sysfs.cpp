/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/panic.h>
#include <onyx/sysfs.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

struct sysfs_object sysfs_root = {
    .name = (char *) "",
    .inode = (ino_t) &sysfs_root,
    .perms = 0644 | S_IFDIR,
};

struct inode *sysfs_root_ino = nullptr;

void sysfs_setup_fops(struct inode *ino);

struct inode *sysfs_create_inode_for_file(struct sysfs_object *f)
{
    struct inode *ino = inode_create(false);
    if (!ino)
        return nullptr;

    ino->i_nlink = 1;
    ino->i_mode = f->perms;
    ino->i_sb = sysfs_root_ino->i_sb;
    ino->i_dev = sysfs_root_ino->i_dev;
    ino->i_inode = (ino_t) f;
    ino->i_flags = INODE_FLAG_DONT_CACHE;

    sysfs_setup_fops(ino);

    return ino;
}

struct inode *sysfs_creat(const char *pathname, int mode, struct dentry *dentry)
{
    return errno = EPERM, nullptr;
}

/* Note: Returns with a reference to the return obj if !nullptr */
struct sysfs_object *sysfs_get_obj(struct sysfs_object *file, const char *name)
{
    spin_lock(&file->dentry_lock);

    list_for_every (&file->dentries)
    {
        struct sysfs_object *obj = container_of(l, struct sysfs_object, dentry_node);

        if (!strcmp(obj->name, name))
        {
            object_ref(&obj->obj);
            spin_unlock(&file->dentry_lock);
            return obj;
        }
    }

    spin_unlock(&file->dentry_lock);

    return nullptr;
}

struct inode *sysfs_open(struct dentry *dir, const char *name)
{
    struct inode *node = dir->d_inode;
    struct sysfs_object *file = (struct sysfs_object *) node->i_inode;
    assert(file != nullptr);

    if (!S_ISDIR(node->i_mode))
        return errno = ENOTDIR, nullptr;

    struct sysfs_object *o = sysfs_get_obj(file, name);

    if (!o)
    {
        return errno = ENOENT, nullptr;
    }

    struct inode *ino = sysfs_create_inode_for_file(o);

    if (ino)
    {
        superblock_add_inode(node->i_sb, ino);
    }
    else
    {
        object_unref(&o->obj);
    }

    return ino;
}

size_t sysfs_read(size_t offset, size_t sizeofread, void *buffer, struct file *this_)
{
    struct sysfs_object *file = (struct sysfs_object *) this_->f_ino->i_inode;
    assert(file != nullptr);

    if (file->read)
        return file->read(buffer, sizeofread, offset);
    else
        return -ENOSYS;
}

size_t sysfs_write(size_t offset, size_t sizeofwrite, void *buffer, struct file *this_)
{
    struct sysfs_object *file = (struct sysfs_object *) this_->f_ino->i_inode;
    assert(file != nullptr);

    if (file->write)
        return file->write(buffer, sizeofwrite, offset);
    else
        return errno = ENOSYS, (size_t) -1;
}

void sysfs_init()
{
    INIT_LIST_HEAD(&sysfs_root.dentries);
    /* If this_ function fails, just panic. sysfs is crucial */
    struct inode *root = inode_create(false);
    assert(root != nullptr);

    struct superblock *sb = (superblock *) zalloc(sizeof(*sb));

    assert(sb != nullptr);

    superblock_init(sb);

    root->i_sb = sb;
    root->i_inode = (ino_t) &sysfs_root;
    root->i_nlink = 1;
    root->i_mode = 0755 | S_IFDIR;

    sysfs_root_ino = root;

    auto ex = dev_register_blockdevs(0, 1, 0, nullptr, "sysfs");
    if (ex.has_error())
        return;

    auto dev = ex.value();

    root->i_dev = dev->dev();
    sysfs_setup_fops(root);

    /* Spawn the standard sysfs directories */
    dev_create_sysfs();
}

INIT_LEVEL_VERY_EARLY_CORE_ENTRY(sysfs_init);

void sysfs_mount()
{
    if (sysfs_root_ino)
    {
        if (mount_fs(sysfs_root_ino, "/sys") < 0)
            panic("sysfs_mount: Could not mount /sys\n");
    }
}

off_t sysfs_getdirent(struct dirent *buf, off_t off, struct file *_file)
{
    struct sysfs_object *file = (struct sysfs_object *) _file->f_ino->i_inode;
    assert(file != nullptr);

    spin_lock(&file->dentry_lock);

    struct sysfs_object *f = nullptr;
    off_t advanced = 0;

    list_for_every (&file->dentries)
    {
        if (advanced++ == off)
        {
            f = container_of(l, struct sysfs_object, dentry_node);
            object_ref(&f->obj);
        }
    }

    spin_unlock(&file->dentry_lock);

    if (!f)
        return 0;

    strlcpy(buf->d_name, f->name, 256);
    buf->d_ino = f->inode;
    buf->d_off = off;
    buf->d_reclen = sizeof(struct dirent) - (256 - (strlen(buf->d_name) + 1));

    if (S_ISDIR(f->perms))
        buf->d_type = DT_DIR;
    else if (S_ISBLK(f->perms))
        buf->d_type = DT_BLK;
    else if (S_ISCHR(f->perms))
        buf->d_type = DT_CHR;
    else if (S_ISLNK(f->perms))
        buf->d_type = DT_LNK;
    else if (S_ISREG(f->perms))
        buf->d_type = DT_REG;
    else
        buf->d_type = DT_UNKNOWN;

    object_unref(&f->obj);

    return off + 1;
}

int sysfs_stat(struct stat *buf, struct file *node)
{
    memset(buf, 0, sizeof(struct stat));

    struct sysfs_object *file = (struct sysfs_object *) node->f_ino->i_inode;
    buf->st_mode = file->perms;

    buf->st_ino = node->f_ino->i_inode;
    buf->st_dev = node->f_ino->i_dev;

    return 0;
}

struct file_ops sysfs_ops = {
    .read = sysfs_read,
    .write = sysfs_write,
    .open = sysfs_open,
    .getdirent = sysfs_getdirent,
    .creat = sysfs_creat,
    .stat = sysfs_stat,
};

void sysfs_setup_fops(struct inode *ino)
{
    ino->i_fops = &sysfs_ops;
}

void sysfs_release(struct object *obj)
{
}

int sysfs_object_init(const char *name, struct sysfs_object *obj)
{
    char *namedup = strdup(name);
    if (!namedup)
        return -ENOMEM;

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
    if (!parent)
        parent = &sysfs_root;

    obj->parent = parent;

    __sysfs_append(obj, parent);
}

int sysfs_init_and_add(const char *name, struct sysfs_object *obj, struct sysfs_object *parent)
{
    int st = sysfs_object_init(name, obj);

    if (st < 0)
        return st;

    sysfs_add(obj, parent);

    return 0;
}
