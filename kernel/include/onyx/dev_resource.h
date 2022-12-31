/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_DEV_RESOURCE_H
#define _ONYX_DEV_RESOURCE_H

#include <stdint.h>

#include <onyx/list.h>

// TODO: Do IRQ flags need to be here? So something like install_irq can look at them
// and do the correct set up.
#define DEV_RESOURCE_FLAG_IO_PORT      (1 << 0)
#define DEV_RESOURCE_FLAG_MEM          (1 << 1)
#define DEV_RESOURCE_FLAG_IRQ          (1 << 2)
#define DEV_RESOURCE_FLAG_PREFETCHABLE (1 << 3)

/**
 * @brief Represents a generic device resource.
 *        For example, an IRQ, mmio range or IO port range.
 *
 */
class dev_resource
{
    unsigned long start_;
    unsigned long end_;
    uint32_t flags_;
    uint32_t bus_index_{0};

public:
    list_head_cpp<dev_resource> resource_list_node_;

    constexpr dev_resource(unsigned long start, unsigned long end, uint32_t flags)
        : start_{start}, end_{end}, flags_{flags}, resource_list_node_{this}
    {
    }

    /**
     * @brief Retrieves the start of the resource
     *
     * @return Start of the resource
     */
    unsigned long start() const
    {
        return start_;
    }

    /**
     * @brief Retrieves the end of the resource
     *
     * @return End of the resource
     */
    unsigned long end() const
    {
        return end_;
    }

    /**
     * @brief Retrieves the size of the resource
     *
     * @return Size of the resource
     */
    unsigned long size() const
    {
        return end_ - start_ + 1;
    }

    /**
     * @brief Sets the start and end of the resource
     *
     * @param start Start of the resource
     * @param end  End of the resource
     */
    void set_limits(unsigned long start, unsigned long end)
    {
        start_ = start;
        end_ = end;
    }

    /**
     * @brief Retrieve the flags of the resource
     *
     * @return Flags of the resource
     */
    uint32_t flags() const
    {
        return flags_;
    }

    /**
     * @brief Retrieve a reference to the flags of the resource
     *
     * @return Reference to the flags of the resource
     */
    uint32_t& flags()
    {
        return flags_;
    }

    /**
     * @brief Set the bus-specific index of this device resource
     *
     * @param i Index
     */
    void set_bus_index(uint32_t i)
    {
        bus_index_ = i;
    }

    /**
     * @brief Get the bus index of the device resource
     *
     * @return Bus index (if not set, 0)
     */
    uint32_t bus_index() const
    {
        return bus_index_;
    }
};

#endif
