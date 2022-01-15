/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <sys/types.h>

#include <onyx/dev.h>
#include <onyx/majorminor.h>
#include <onyx/compiler.h>
#include <onyx/panic.h>
#include <onyx/tmpfs.h>
#include <onyx/vfs.h>
#include <onyx/init.h>
#include <onyx/file.h>
#include <onyx/hashtable.hpp>
#include <onyx/fnv.h>
#include <onyx/fs_mount.h>
#include <onyx/tmpfs.h>
#include <onyx/dentry.h>

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

fnv_hash_t internal_chardev_reg_hash(internal_dev_registry_struct& c)
{
    return major_hash(c.major);
}

class dev_registry
{
public:
    spinlock gendev_lock_;
    cul::hashtable2<internal_dev_registry_struct, 256, fnv_hash_t, internal_chardev_reg_hash> gendevs_;

    dev_registry() : gendev_lock_{}, gendevs_{}
    {}

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

        list_for_every(list)
        {
            auto chardev_reg = container_of(l, internal_dev_registry_struct, list_node);

            if (chardev_reg->major != major)
                continue;

            if (!minor_valid)
                return true;

            if (check_for_overlap(minor, minor + nr_devs, chardev_reg->minor, chardev_reg->minor + chardev_reg->c->nr_devs()))
                return true;
        }

        return false;
    }

    expected<unsigned int, bool> allocate_device_number(dev_t desired, unsigned int nr_devs)
    {
        for(unsigned int i = 1; i < MAX_MAJOR_NR; i++)
        {
            if (!dev_number_is_allocated(MKDEV(i, MINOR(desired)), nr_devs))
                return MKDEV(i, MINOR(desired));
        }

        return unexpected<bool>{false};
    }
};

dev_registry chardevs{};
dev_registry blockdevs{};

}

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
static expected<gendev *, int> dev_register_gendevs(dev_registry &reg, dev_t dev, unsigned int nr_devices, unsigned int flags,
                                             const file_ops *fops, cul::string&& name)
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
expected<chardev *, int> dev_register_chardevs(dev_t dev, unsigned int nr_devices, unsigned int flags,
                                             const file_ops *fops, cul::string&& name)
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
expected<blkdev *, int> dev_register_blockdevs(dev_t dev, unsigned int nr_devices, unsigned int flags,
                                             const file_ops *fops, cul::string&& name)
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

    list_for_every(list)
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

    list_for_every(list)
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

struct devfs_registration
{
    list_head_cpp<devfs_registration> list_node;
    dev_t dev;
    mode_t mode;
    const cul::string& name;

    devfs_registration(const cul::string& name, dev_t dev, mode_t mode) : list_node{this}, dev{dev}, mode{mode}, name{name} {}
};

// List of devfs_registration objects
static list_head devfs_list = LIST_HEAD_INIT(devfs_list);
static spinlock devfs_list_lock;

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

    auto reg = make_unique<devfs_registration>(name_, dev_, mode);

    if (!reg)
        return -ENOMEM;

    list_add_tail(&reg->list_node, &devfs_list);

    reg.release();

    return 0;
}

/**
 * @brief Open a file
 * 
 * @param dir Dentry of the current directory
 * @param name Name of the file
 * @return Pointer to the inode, or nullptr with errno set
 */
inode *devfs_open(dentry *dir, const char *name)
{
	scoped_lock g{devfs_list_lock};
    devfs_registration *reg = nullptr;
    ino_t inum = 1;

    list_for_every(&devfs_list)
    {
        auto dev_reg = list_head_cpp<devfs_registration>::self_from_list_head(l);
    
        if (dev_reg->name == name)
        {
            reg = dev_reg;
            break;
        }

        inum++;
    }

    g.unlock();

    if (!reg)
    {
        return errno = ENOENT, nullptr;
    }

    auto sb = (tmpfs_superblock *) dir->d_inode->i_sb;

    auto ino = sb->create_inode(reg->mode, reg->dev);

    if (!ino)
        return errno = ENOMEM, nullptr;
    
    ino->i_inode = inum;
    
    return ino;
}

off_t devfs_getdirent(struct dirent *buf, off_t off, struct file *file)
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
		scoped_lock g{devfs_list_lock};

		off_t c = 0;
		list_for_every(&devfs_list)
        {	
			auto d = list_head_cpp<devfs_registration>::self_from_list_head(l);

            if(off > c++ + 2)
				continue;

            buf->d_ino = c;
            auto len = d->name.length();
	        memcpy(buf->d_name, d->name.c_str(), len);
	        buf->d_name[len] = '\0';
	        buf->d_reclen = sizeof(dirent) - (256 - (len + 1));

            if (S_ISBLK(d->mode))
                buf->d_type = DT_BLK;
            else
                buf->d_type = DT_CHR;

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

    auto new_fs = make_unique<tmpfs_superblock>();
    if (!new_fs)
    {
        dev_unregister_dev(ex.value(), true);
        return nullptr;
    }
    
    auto fops = make_unique<file_ops>(tmpfs_fops);

    if (!fops)
    {
        dev_unregister_dev(ex.value(), true);
        return nullptr;
    }

    fops->open = devfs_open;
    fops->getdirent = devfs_getdirent;

    new_fs->override_file_ops(fops.release());

    superblock_init(new_fs.get());
    new_fs->s_devnr = ex.value()->dev();

    auto node = new_fs->create_inode(S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    if (!node)
    {
        dev_unregister_dev(ex.value(), true);
        return errno = ENOMEM, nullptr;
    }

    new_fs.release();

    return node;
}

__init void devfs_init()
{
    if (fs_mount_add(devfs_mount, FS_MOUNT_PSEUDO_FS, "devfs") < 0)
        panic("Could not register devfs");
}
