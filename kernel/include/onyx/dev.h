/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_DEV_H
#define _ONYX_DEV_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <onyx/culstring.h>
#include <onyx/dev_resource.h>
#include <onyx/list.h>
#include <onyx/majorminor.h>
#include <onyx/spinlock.h>
#include <onyx/sysfs.h>
#include <onyx/vfs.h>

#include <onyx/expected.hpp>
#include <onyx/memory.hpp>

/**
 * @brief Represents a generic char/block device inside the kernel
 * Each gendev represents N devices from a specific MAJOR:MINOR pair until MAJOR:MINOR+N
 */
class gendev
{
protected:
    dev_t dev_;
    unsigned int nr_devs_;
    cul::string name_;
    const file_ops *fops_;
    bool is_character_dev_;

public:
    void *private_;
    gendev() = default;

    gendev(dev_t dev, unsigned int nr, const cul::string &name, const file_ops *fops)
        : dev_{dev}, nr_devs_{nr}, name_{name}, fops_{fops}, is_character_dev_{}, private_{}
    {
    }

    /**
     * @brief Return the device number of the gendev
     *
     * @return The device number
     */
    dev_t dev() const
    {
        return dev_;
    }

    /**
     * @brief Return the number of devices that are backed by this gendev
     *
     * @return The number of devices corresponding to this gendev
     */
    unsigned int nr_devs() const
    {
        return nr_devs_;
    }

    /**
     * @brief Return the name
     *
     * @return A const ref to the name
     */
    const cul::string &name() const
    {
        return name_;
    }

    /**
     * @brief Return the file_ops corresponding to the gendev
     *
     * @return A pointer to the file_ops
     */
    const file_ops *fops() const
    {
        return fops_;
    }

    /**
     * @brief Set the dev
     *
     * @param d The device number
     */
    void set_dev(dev_t d)
    {
        dev_ = d;
    }

    /**
     * @brief Set the number of devices
     *
     * @param nr_devs Number of devices
     */
    void set_nr_devs(unsigned int nr_devs)
    {
        nr_devs_ = nr_devs;
    }

    /**
     * @brief Set the name of the gendev
     *
     * @param name Const ref to the name string
     * @return True if succesful, false if OOM on copying
     */
    bool set_name(const cul::string &name)
    {
        name_ = name;

        return !name_.empty();
    }

    /**
     * @brief Set the file_ops of the gendev
     *
     * @param f Pointer to const file_ops
     */
    void set_fops(const file_ops *f)
    {
        fops_ = f;
    }

    /**
     * @brief See if this generic device is a character or block device
     *
     * @return True if character device, else false (and block dev)
     */
    bool is_chrdev() const
    {
        return is_character_dev_;
    }

    /**
     * @brief Publish the character/block device to user-space and devfs
     *
     * @return 0 on success, else negative error codes
     */
    int show(mode_t mode);
};

class chardev : public gendev
{
public:
    chardev() = default;

    chardev(dev_t dev, unsigned int nr, const cul::string &name, const file_ops *fops)
        : gendev{dev, nr, name, fops}
    {
        is_character_dev_ = true;
    }
};

class blkdev : public gendev
{
public:
    blkdev() = default;

    blkdev(dev_t dev, unsigned int nr, const cul::string &name, const file_ops *fops)
        : gendev{dev, nr, name, fops}
    {
        is_character_dev_ = false;
    }
};

#define DEV_REGISTER_STATIC_DEV (1 << 0) // dev is a valid device that is desired by the user

/**
 * @brief Register a character device with the kernel
 *
 * @param dev             If flags & DEV_REGISTER_STATIC_DEV, this specifies the desired
 *                        (major, minor) device number; else, specifies the base minor number.
 * @param nr_devices      The number of desired minor character devices
 * @param flags           Flags, see above
 * @param fops            A pointer to the file_ops of the character device.
 * @param name            A rvalue reference of the name
 * @return Expected object containing either a chardev* or the int error code
 */
expected<chardev *, int> dev_register_chardevs(dev_t dev, unsigned int nr_devices,
                                               unsigned int flags, const file_ops *fops,
                                               cul::string &&name);

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
                                               cul::string &&name);

/**
 * @brief Find a chardev by device number
 * TODO: This function is not safe for unloading
 * @param dev Device number
 * @return A pointer to the chardev, or NULL
 */
chardev *dev_find_chr(dev_t dev);

/**
 * @brief Find a blockdev by device number
 * TODO: This function is not safe for unloading
 * @param dev Device number
 * @return A pointer to the blockdev, or NULL
 */
blkdev *dev_find_block(dev_t dev);

/**
 * @brief Unregister a character/block device from the kernel
 *
 * @param dev Pointer to the generic device
 * @param is_block True if it's a block device, else false. Defaults to false
 * @return 0 on success, else negative error code
 */
int dev_unregister_dev(gendev *dev, bool is_block = false);

struct bus;
struct device;

struct driver
{
    const char *name;
    struct bus *bus;
    struct spinlock device_list_lock;
    struct extrusive_list_head devices;
    unsigned long ref;
    void *devids;

    int (*probe)(device *dev);
    void (*shutdown)(device *dev);
    void (*resume)(device *dev);
    void (*suspend)(device *dev);

    list_head_cpp<driver> bus_type_node;
};

struct device
{
    device *parent;
    const char *name;
    struct bus *bus;
    driver *driver_;
    sysfs_object device_sysfs;
    void *priv;

    extrusive_list_head children;
    list_head_cpp<device> device_list_node;

    spinlock resource_list_lock_;
    list_head resource_list_;

    device(const char *name, struct bus *bus, device *parent)
        : parent{parent}, name{name}, bus{bus}, driver_{nullptr}, device_sysfs{}, priv{},
          children{}, device_list_node{this}, resource_list_lock_{}, resource_list_{}
    {
        spinlock_init(&resource_list_lock_);
        INIT_LIST_HEAD(&resource_list_);
    }

    virtual ~device()
    {
    }

    virtual int shutdown()
    {
        return 0;
    }

    virtual int resume()
    {
        return 0;
    }

    virtual int suspend()
    {
        return 0;
    }

    /**
     * @brief Adds a resource to the device
     *
     * @param resource Pointer to the resource
     */
    void add_resource(dev_resource *resource)
    {
        scoped_lock g{resource_list_lock_};

        list_add_tail(&resource->resource_list_node_, &resource_list_);
    }

    /**
     * @brief Removes a resource from the device
     *
     * @param resource Pointer to the resource
     */
    void remove_resource(dev_resource *resource)
    {
        scoped_lock g{resource_list_lock_};

        list_remove(&resource->resource_list_node_);
    }

    /**
     * @brief Calls a function for every resource in the device
     *
     * @tparam Callable Callable function type
     * @param c Callable function
     */
    template <typename Callable>
    void for_every_resource(Callable c)
    {
        scoped_lock g{resource_list_lock_};

        list_for_every (&resource_list_)
        {
            auto resource = list_head_cpp<dev_resource>::self_from_list_head(l);

            if (!c(resource))
                return;
        }
    }

    /**
     * @brief Retrieves a device's resource
     *
     * @param type Type of the device (see dev_resource.h's flags)
     * @param index Index of the resource inside the list of the resource type
     *              e.g: index 0 is the first of the IRQ resources of the device
     * @return Pointer to the dev_resource found, or nullptr if not found.
     */
    dev_resource *get_resource(uint32_t type, unsigned int index = 0)
    {
        dev_resource *r = nullptr;
        for_every_resource([&](dev_resource *resource) -> bool {
            if (resource->flags() & type && index-- == 0)
            {
                r = resource;
                return false;
            }

            return true;
        });

        return r;
    }

    /**
     * @brief Retrieves a device's resource using the bus index
     *
     * @param type Type of the device (see dev_resource.h's flags)
     * @param index Bus specific index of the resource
     * @return Pointer to the dev_resource found, or nullptr if not found.
     */
    dev_resource *get_resource_busindex(uint32_t type, unsigned int index)
    {
        dev_resource *r = nullptr;
        for_every_resource([&](dev_resource *resource) -> bool {
            if (resource->flags() & type && resource->bus_index() == index)
            {
                r = resource;
                return false;
            }

            return true;
        });

        return r;
    }
};

struct bus;

/* bus_init - Initialize a bus structure */
int bus_init(struct bus *bus);

struct bus
{
    /* Name of the bus */
    const char *name;
    spinlock bus_lock;
    /* List of every device connected to this bus */
    list_head device_list_head;
    list_head child_buses;
    sysfs_object bus_sysfs;

    int (*shutdown_bus)(bus *);
    int (*suspend_bus)(bus *);
    int (*resume_bus)(bus *);
    list_head_cpp<bus> bus_list_node;
    list_head_cpp<bus> bus_type_node;
    list_head_cpp<bus> child_buses_node;

    virtual void probe(driver *drv)
    {
        list_for_every (&device_list_head)
        {
            auto dev = list_head_cpp<device>::self_from_list_head(l);
            (void) dev;
            // TODO
        }
    }

    template <typename Callable>
    void for_every_device(Callable cb)
    {
        scoped_lock g{bus_lock};
        list_for_every (&device_list_head)
        {
            auto dev = list_head_cpp<device>::self_from_list_head(l);
            if (!cb(dev))
                return;
        }
    }

    bus(const char *name)
        : name{name}, bus_lock{}, device_list_head{}, bus_sysfs{}, shutdown_bus{}, suspend_bus{},
          resume_bus{}, bus_list_node{this}, bus_type_node{this}, child_buses_node{this}
    {
        INIT_LIST_HEAD(&device_list_head);
        INIT_LIST_HEAD(&child_buses);
        bus_init(this);
    }

    void add_bus(bus *b)
    {
        scoped_lock g{bus_lock};
        list_add_tail(&b->child_buses_node, &child_buses);
    }

    template <typename Callable>
    void for_every_child_bus_unlocked(Callable cb)
    {
        list_for_every (&child_buses)
        {
            auto b = list_head_cpp<bus>::self_from_list_head(l);
            if (!cb(b))
                return;
        }
    }

    template <typename Callable>
    void for_every_child_bus(Callable cb)
    {
        scoped_lock g{bus_lock};
        for_every_child_bus_unlocked<Callable>(cb);
    }
};

/* bus_init - Initialize a device structure */
int device_init(struct device *dev);

/* bus_register - Register a bus */
void bus_register(struct bus *bus);

/* bus_unregister - Unregister a bus */
void bus_unregister(struct bus *bus);

/* bus_add_device - Add a device to a bus */
void bus_add_device(struct bus *bus, struct device *device);

/* bus_find_device - Find a device on the bus */
struct device *bus_find_device(struct bus *bus, const char *devname);

/* bus_shutdown - Shutdown every device on the bus */
void bus_shutdown(struct bus *bus);

/* bus_shutdown_every - Shutdown every bus */
void bus_shutdown_every(void);

/* bus_suspend_every - Suspend every bus */
void bus_suspend_every(void);

void dev_create_sysfs(void);

void driver_register_device(struct driver *driver, struct device *dev);

void driver_deregister_device(struct driver *driver, struct device *dev);

#endif
