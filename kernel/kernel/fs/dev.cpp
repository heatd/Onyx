/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
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

#include <onyx/compiler.h>
#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/file.h>
#include <onyx/fnv.h>
#include <onyx/fs_mount.h>
#include <onyx/init.h>
#include <onyx/libfs.h>
#include <onyx/majorminor.h>
#include <onyx/panic.h>
#include <onyx/tmpfs.h>
#include <onyx/types.h>
#include <onyx/vfs.h>

#include <onyx/hashtable.hpp>

namespace
{

struct internal_dev_registry_struct
{
    unsigned int major;
    unsigned int minor;
    gendev *c;
    struct list_head list_node;
};

fnv_hash_t major_hash(unsigned int major)
{
    return fnv_hash(&major, sizeof(major));
}

fnv_hash_t internal_chardev_reg_hash(internal_dev_registry_struct &c)
{
    return major_hash(c.major);
}

class dev_registry
{
public:
    spinlock gendev_lock_;
    cul::hashtable2<internal_dev_registry_struct, 256, fnv_hash_t, internal_chardev_reg_hash>
        gendevs_;

    constexpr dev_registry() : gendev_lock_{}, gendevs_{}
    {
    }

    int major_to_index(dev_t major)
    {
        return gendevs_.get_hashtable_index(major_hash(major));
    }

    /**
     * @brief Check if a device number is allocated
     *
     * @param dev         Dev number to check
     * @param nr_devs     Number of desired minor numbers
     * @param minor_valid True if the minor in dev is valid, else just look at the majors.
                          Defaults to false
     *
     * @return True if allocated, else false
     */
    bool dev_number_is_allocated(dev_t dev, unsigned int nr_devs, bool minor_valid = false)
    {
        auto major = MAJOR(dev);
        auto minor = MINOR(dev);
        auto major_index = major_to_index(major);

        auto list = gendevs_.get_hashtable(major_index);

        list_for_every (list)
        {
            auto chardev_reg = container_of(l, internal_dev_registry_struct, list_node);

            if (chardev_reg->major != major)
                continue;

            if (!minor_valid)
                return true;

            if (check_for_overlap(minor, minor + nr_devs, chardev_reg->minor,
                                  chardev_reg->minor + chardev_reg->c->nr_devs()))
                return true;
        }

        return false;
    }

    expected<unsigned int, bool> allocate_device_number(dev_t desired, unsigned int nr_devs)
    {
        for (unsigned int i = 1; i < MAX_MAJOR_NR; i++)
        {
            if (!dev_number_is_allocated(MKDEV(i, MINOR(desired)), nr_devs))
                return MKDEV(i, MINOR(desired));
        }

        return unexpected<bool>{false};
    }
};

dev_registry chardevs{};
dev_registry blockdevs{};

} // namespace

/**
 * @brief Register a generic device with the kernel
 *
 * @param dev             If flags & DEV_REGISTER_STATIC_DEV, this specifies the desired
 *                        (major, minor) device number; else, specifies the base minor number.
 * @param nr_devices      The number of desired minor devices
 * @param flags           Flags, see above
 * @param fops            A pointer to the file_ops of the device.
 * @param name            A rvalue reference of the name
 * @return Expected object containing either a chardev *or the int error code
 */
static expected<gendev *, int> dev_register_gendevs(dev_registry &reg, dev_t dev,
                                                    unsigned int nr_devices, unsigned int flags,
                                                    const file_ops *fops, cul::string &&name)
{
    scoped_lock g{reg.gendev_lock_};

    // Too many devices
    if (nr_devices > MINOR_MASK)
        return unexpected<int>{-EINVAL};

    dev_t desired = dev;

    if (flags & DEV_REGISTER_STATIC_DEV)
    {
        if (reg.dev_number_is_allocated(desired, nr_devices, true))
            return unexpected<int>{-EBUSY};
    }
    else
    {
        auto ex = reg.allocate_device_number(desired, nr_devices);

        if (ex.has_error())
            return unexpected<int>{-ESRCH};

        dev = ex.value();
    }

    auto dev_reg = make_unique<internal_dev_registry_struct>();
    if (!dev_reg)
        return unexpected<int>{-ENOMEM};

    unique_ptr<gendev> chr;

    // __ugly__ but it works
    if (&reg == &chardevs)
        chr.reset(new chardev(dev, nr_devices, name, cul::move(fops)));
    else
        chr.reset(new blkdev(dev, nr_devices, name, cul::move(fops)));

    if (!chr)
        return unexpected<int>{-ENOMEM};

    dev_reg->major = MAJOR(dev);
    dev_reg->minor = MINOR(dev);
    dev_reg->c = chr.get();

    reg.gendevs_.add_element(*dev_reg);

    dev_reg.release();

    return chr.release();
}

/**
 * @brief Register a character device with the kernel
 *
 * @param dev             If flags & DEV_REGISTER_STATIC_DEV, this specifies the desired
 *                        (major, minor) device number; else, specifies the base minor number.
 * @param nr_devices      The number of desired minor character devices
 * @param flags           Flags, see above
 * @param fops            A pointer to the file_ops of the character device.
 * @param name            A rvalue reference of the name
 * @return Expected object containing either a chardev *or the int error code
 */
expected<chardev *, int> dev_register_chardevs(dev_t dev, unsigned int nr_devices,
                                               unsigned int flags, const file_ops *fops,
                                               cul::string &&name)
{
    auto ex = dev_register_gendevs(chardevs, dev, nr_devices, flags, fops, cul::move(name));

    // Yucky :(
    if (ex.has_error())
        return unexpected<int>{ex.error()};

    return (chardev *) ex.value();
}

/**
 * @brief Register a block device with the kernel
 *
 * @param dev             If flags & DEV_REGISTER_STATIC_DEV, this specifies the desired
 *                        (major, minor) device number; else, specifies the base minor number.
 * @param nr_devices      The number of desired minor block devices
 * @param flags           Flags, see above
 * @param fops            A pointer to the file_ops of the block device.
 * @param name            A rvalue reference of the name
 * @return Expected object containing either a chardev *or the int error code
 */
expected<blkdev *, int> dev_register_blockdevs(dev_t dev, unsigned int nr_devices,
                                               unsigned int flags, const file_ops *fops,
                                               cul::string &&name)
{
    auto ex = dev_register_gendevs(blockdevs, dev, nr_devices, flags, fops, cul::move(name));

    // Yucky :(
    if (ex.has_error())
        return unexpected<int>{ex.error()};

    return (blkdev *) ex.value();
}

/**
 * @brief Find a dev by device number
 * TODO: This function is not safe for unloading
 * @param dev Device number
 * @return A pointer to the chardev, or NULL
 */
static gendev *dev_find_generic(dev_registry &reg, dev_t dev)
{
    scoped_lock g{reg.gendev_lock_};

    auto major = MAJOR(dev);
    auto minor = MINOR(dev);
    auto list = reg.gendevs_.get_hashtable(reg.major_to_index(major));

    list_for_every (list)
    {
        auto cdev_reg = container_of(l, internal_dev_registry_struct, list_node);

        if (cdev_reg->major != major)
            continue;

        if (cdev_reg->minor <= minor && cdev_reg->minor + cdev_reg->c->nr_devs() > minor)
        {
            return reinterpret_cast<chardev *>(cdev_reg->c);
        }
    }

    return nullptr;
}

/**
 * @brief Find a chardev by device number
 * TODO: This function is not safe for unloading
 * @param dev Device number
 * @return A pointer to the chardev, or NULL
 */
chardev *dev_find_chr(dev_t dev)
{
    return (chardev *) dev_find_generic(chardevs, dev);
}

/**
 * @brief Find a chardev by device number
 * TODO: This function is not safe for unloading
 * @param dev Device number
 * @return A pointer to the blkdev, or NULL
 */
blkdev *dev_find_block(dev_t dev)
{
    return (blkdev *) dev_find_generic(blockdevs, dev);
}

/**
 * @brief Unregister a character/block device from the kernel
 *
 * @param dev Pointer to the generic device
 * @param is_block True if it's a block device, else false. Defaults to false
 * @return 0 on success, else negative error code
 */
int dev_unregister_dev(gendev *dev, bool is_block)
{
    auto &registry = is_block ? blockdevs : chardevs;
    scoped_lock g{registry.gendev_lock_};

    auto major = MAJOR(dev->dev());
    auto minor = MINOR(dev->dev());
    auto list = registry.gendevs_.get_hashtable(registry.major_to_index(major));

    list_for_every (list)
    {
        auto cdev_reg = container_of(l, internal_dev_registry_struct, list_node);

        if (cdev_reg->major != major)
            continue;

        if (cdev_reg->minor == minor && cdev_reg->c == dev)
        {
            // Remove the registration and free the device objects
            list_remove(&cdev_reg->list_node);
            delete cdev_reg;
            delete dev;
            return 0;
        }
    }

    return -ENODEV;
}

struct devfs_file
{
    list_head_cpp<devfs_file> list_node;
    list_head children;
    dev_t dev;
    mode_t mode;
    ino_t ino;
    const cul::string name;

    constexpr devfs_file(const cul::string &name, dev_t dev, mode_t mode, ino_t inode)
        : list_node{this}, dev{dev}, mode{mode}, ino{inode}, name{name}
    {
        INIT_LIST_HEAD(&children);
    }

    constexpr devfs_file(dev_t dev, mode_t mode, ino_t inode)
        : list_node{this}, dev{dev}, mode{mode}, ino{inode}, name{}
    {
        INIT_LIST_HEAD(&children);
    }
};

#define DEVFS_ROOT_INO         2
#define DEVFS_RESERVED_INO_END 10
// List of devfs_registration objects
static constinit struct devfs_file devfs_root = {
    0, S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, DEVFS_ROOT_INO};
static spinlock devfs_list_lock;
static ino_t next_inode = DEVFS_RESERVED_INO_END;

static void devfs_add_entry(unique_ptr<devfs_file> &&file, devfs_file *dir = &devfs_root)
{
    list_add_tail(&file->list_node, &dir->children);
    file.release();
}

static devfs_file *devfs_open_internal(std::string_view name, devfs_file *dir = &devfs_root)
{
    if (!S_ISDIR(dir->mode))
        return nullptr;

    list_for_every (&dir->children)
    {
        auto dev_reg = list_head_cpp<devfs_file>::self_from_list_head(l);
        if (!name.compare(dev_reg->name))
            return dev_reg;
    }

    return nullptr;
}

static devfs_file *devfs_open_path(std::string_view path, devfs_file *dir = &devfs_root)
{
    std::string_view::size_type pos = 0;
    while (true)
    {
        pos = path.find_first_not_of('/', pos);
        if (pos == std::string_view::npos)
            break;

        auto path_elem_end = path.find('/', pos);
        if (path_elem_end == std::string_view::npos)
            path_elem_end = path.length();

        std::string_view v = path.substr(pos, path_elem_end - pos);
        pos += v.length() + 1;

        dir = devfs_open_internal(v, dir);
    }

    return dir;
}

/**
 * @brief Publish the character/block device to user-space and devfs
 *
 * @return 0 on success, else negative error codes
 */
int gendev::show(mode_t mode)
{
    scoped_lock g{devfs_list_lock};

    if (is_character_dev_)
        mode |= S_IFCHR;
    else
        mode |= S_IFBLK;

    auto reg = make_unique<devfs_file>(name_, dev_, mode, next_inode++);
    if (!reg)
        return -ENOMEM;

    devfs_add_entry(cul::move(reg));
    return 0;
}

/**
 * @brief Publish a device to userspace with a custom name
 *
 * @param custom_name Custom name
 * @param path Path (may be NULL or empty)
 * @param mode File mode
 * @return 0 on success, negative error codes
 */
int gendev::show_with_name(const char *custom_name, const char *path, mode_t mode)
{
    scoped_lock g{devfs_list_lock};

    if (is_character_dev_)
        mode |= S_IFCHR;
    else
        mode |= S_IFBLK;
    cul::string name{custom_name};
    if (!name)
        return -ENOMEM;

    devfs_file *base_dir = devfs_open_path(path);
    if (!base_dir)
        return -ENOENT;

    auto reg = make_unique<devfs_file>(cul::move(name), dev_, mode, next_inode++);
    if (!reg)
        return -ENOMEM;
    devfs_add_entry(cul::move(reg), base_dir);
    return 0;
}

static inode *devfs_open(dentry *dir, const char *name);
static off_t devfs_getdirent(struct dirent *buf, off_t off, struct file *file);

static const struct file_ops devfs_root_ops = {
    .open = devfs_open,
    .getdirent = devfs_getdirent,
    .creat = libfs_no_creat,
    .link = libfs_no_link,
    .symlink = libfs_no_symlink,
    .ftruncate = libfs_no_ftruncate,
    .mkdir = libfs_no_mkdir,
    .mknod = libfs_no_mknod,
    .readlink = libfs_no_readlink,
    .unlink = libfs_no_unlink,
    .fallocate = libfs_no_fallocate,
};

inode *devfs_create_inode(devfs_file *file, struct superblock *sb)
{
    struct inode *inode = inode_create(false);
    if (!inode)
        return nullptr;
    inode->i_atime = inode->i_mtime = inode->i_ctime = clock_get_posix_time();
    inode->i_inode = file->ino;
    inode->i_dev = sb->s_devnr;
    inode->i_rdev = file->dev;
    inode->i_fops = (struct file_ops *) &devfs_root_ops;
    inode->i_mode = file->mode;
    inode->i_helper = file;
    inode->i_sb = sb;
    inode->i_nlink = S_ISDIR(file->mode) ? 2 : 1;
    /* TODO: nlink is bound to change dynamically? */

    if (inode_is_special(inode))
    {
        int st = inode_special_init(inode);
        if (st < 0)
        {
            errno = -st;
            free(inode);
            return nullptr;
        }
    }

    return inode;
}

/**
 * @brief Open a file
 *
 * @param dir Dentry of the current directory
 * @param name Name of the file
 * @return Pointer to the inode, or nullptr with errno set
 */
static inode *devfs_open(dentry *dir, const char *name)
{
    scoped_lock g{devfs_list_lock};
    devfs_file *dev_dir = (devfs_file *) dir->d_inode->i_helper;
    DCHECK(dev_dir != nullptr);
    devfs_file *reg = nullptr;

    list_for_every (&dev_dir->children)
    {
        auto dev_reg = list_head_cpp<devfs_file>::self_from_list_head(l);

        if (dev_reg->name == name)
        {
            reg = dev_reg;
            break;
        }
    }

    g.unlock();

    if (!reg)
        return errno = ENOENT, nullptr;

    auto sb = dir->d_inode->i_sb;
    auto ino = devfs_create_inode(reg, sb);
    if (!ino)
        return errno = ENOMEM, nullptr;

    return ino;
}

static off_t devfs_getdirent(struct dirent *buf, off_t off, struct file *file)
{
    auto dent = file->f_dentry;

    buf->d_off = off;

    if (off == 0)
    {
        /* . */
        put_dentry_to_dirent(buf, dent, ".");
    }
    else if (off == 1)
    {
        /* .. */
        auto parent = dentry_parent(dent);
        put_dentry_to_dirent(buf, parent, "..");
        dentry_put(parent);
    }
    else
    {
        scoped_lock g{devfs_list_lock};
        devfs_file *dev_dir = (devfs_file *) dent->d_inode->i_helper;
        DCHECK(dev_dir != nullptr);

        off_t c = 0;
        list_for_every (&dev_dir->children)
        {
            auto d = list_head_cpp<devfs_file>::self_from_list_head(l);

            if (off > c++ + 2)
                continue;

            buf->d_ino = c;
            auto len = d->name.length();
            memcpy(buf->d_name, d->name.c_str(), len);
            buf->d_name[len] = '\0';
            buf->d_reclen = sizeof(dirent) - (256 - (len + 1));

            if (S_ISDIR(d->mode))
                buf->d_type = DT_DIR;
            else if (S_ISBLK(d->mode))
                buf->d_type = DT_BLK;
            else if (S_ISCHR(d->mode))
                buf->d_type = DT_CHR;
            else if (S_ISLNK(d->mode))
                buf->d_type = DT_LNK;
            else if (S_ISREG(d->mode))
                buf->d_type = DT_REG;
            else
                buf->d_type = DT_UNKNOWN;
            return off + 1;
        }

        return 0;
    }

    return off + 1;
}

/**
 * @brief Mount a devfs instance
 *
 * @param dev Traditionally a pointer to blockdev, but our case, unused.
 * @return Pointer to the root inode, or nullptr in case of an error
 */
inode *devfs_mount(blockdev *dev)
{
    auto ex = dev_register_blockdevs(0, 1, 0, nullptr, "devfs");

    if (ex.has_error())
        return errno = -ex.error(), nullptr;

    auto new_fs = make_unique<superblock>();
    if (!new_fs)
    {
        dev_unregister_dev(ex.value(), true);
        return nullptr;
    }

    new_fs->s_devnr = ex.value()->dev();
    new_fs->s_flags |= SB_FLAG_NODIRTY;

    auto node = devfs_create_inode(&devfs_root, new_fs.get());
    if (!node)
    {
        dev_unregister_dev(ex.value(), true);
        return nullptr;
    }

    new_fs.release();

    return node;
}

static void devfs_add_dir(const char *name, mode_t mode)
{
    scoped_lock g{devfs_list_lock};
    auto reg = make_unique<devfs_file>(name, 0, S_IFDIR | mode, next_inode++);
    CHECK(reg != nullptr);

    devfs_add_entry(cul::move(reg));
}

__init void devfs_init()
{
    if (fs_mount_add(devfs_mount, FS_MOUNT_PSEUDO_FS, "devfs") < 0)
        panic("Could not register devfs");
    devfs_add_dir("shm", 0777);
    devfs_add_dir("pts", 0755);
}
