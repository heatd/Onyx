/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_DEVICE_TREE_H
#define _ONYX_DEVICE_TREE_H

#include <libfdt.h>

#include <onyx/culstring.h>
#include <onyx/dev.h>
#include <onyx/driver.h>
#include <onyx/vector.h>

namespace device_tree
{

/**
 * @brief Initialise the device tree subsystem of the kernel
 *
 * @param fdt Pointer to the flattened device tree
 */
void init(void *fdt);

template <typename Type>
Type fdt_to_cpu(Type x);

template <>
inline uint8_t fdt_to_cpu<uint8_t>(uint8_t x)
{
    return x;
}

template <>
inline uint16_t fdt_to_cpu<uint16_t>(uint16_t x)
{
    return fdt16_to_cpu(x);
}

template <>
inline uint32_t fdt_to_cpu<uint32_t>(uint32_t x)
{
    return fdt32_to_cpu(x);
}

/**
 * @brief Enumerate the device tree
 *        Note: Requires dynamic memory allocation
 */
void enumerate();

struct node : public device
{
    cul::string name;
    cul::vector<node *> children;
    node *parent;
    int offset, depth;

    int address_cells{2}, size_cells{1};
    int interrupt_parent{0};

    driver *driver_{nullptr};

    list_head_cpp<node> list_node;

    node(cul::string &&name, int offset, int depth, node *parent = nullptr)
        : device{"", nullptr, parent}, name{name}, parent{parent}, offset{offset}, depth{depth},
          list_node{this}
    {
    }

    /**
     * @brief Gets a property of the node from the device tree
     *
     * @param name Name of the property
     * @param buf Pointer to a buffer
     * @param length Size of the buffer (needs to be the same as the length of the property)
     * @return 0 on success, negative error codes
     */
    int get_property(const char *name, void *buf, size_t length);

    template <typename T>
    int get_property(const char *name, T *ptr)
    {
        int st = get_property(name, ptr, sizeof(T));

        if (st == 0)
            *ptr = fdt_to_cpu(*ptr);
        return st;
    }

    /**
     * @brief Gets a property of the node from the device tree
     *
     * @param name Name of the property
     * @param length Pointer to the length, or negative error codes
     * @return Pointer to property
     */
    const void *get_property(const char *name, int *length);

    /**
     * @brief Open a child node
     *
     * @param name Name of the node
     * @return Pointer to the node, or nullptr
     */
    node *open_node(std::string_view name)
    {
        for (const auto &n : children)
        {
            if (n->name == name)
                return n;
        }

        return nullptr;
    }

    /**
     * @brief Enumerate the device node's resources
     *
     */
    void enumerate_resources();
};

/**
 * @brief Get the root dt node
 *
 * @return Pointer to the root node
 */
node *get_root();

/**
 * @brief Open a device tree node
 *
 * @param path Path of the node
 * @return Pointer to the node
 */
node *open_node(std::string_view path, node *base_node = nullptr);

struct dev_id
{
    // This is matched against the node's 'compatible' property, if it exists
    const char *compatible;
};

/**
 * @brief Register a driver with the device tree subsystem
 *
 * @param driver_
 */
void register_driver(driver *driver_);

/**
 * @brief Map a phandle ID to a node
 *
 * @param phandle phandle ID
 * @return Node that it maps to, or nullptr if not found.
 */
node *map_phandle(uint32_t phandle);

} // namespace device_tree

#endif
