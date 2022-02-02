/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_BUS_TYPE_H
#define _ONYX_BUS_TYPE_H

#include <stdint.h>

#include <onyx/dev.h>

class bus_type
{
    const char *name_;
    spinlock lock_;
    list_head driver_list_;
    spinlock bus_list_lock_;
    list_head bus_list_;

    void probe_buses(driver *drv)
    {
        list_for_every (&bus_list_)
        {
            auto bus = list_head_cpp<struct bus>::self_from_list_head(l);

            bus->probe(drv);
        }
    }

public:
    constexpr bus_type(const char *name)
        : name_{name}, lock_{}, driver_list_{}, bus_list_lock_{}, bus_list_{}
    {
        INIT_LIST_HEAD(&driver_list_);
        INIT_LIST_HEAD(&bus_list_);
    }

    void add_driver(driver *drv)
    {
        scoped_lock g{lock_};
        list_add_tail(&drv->bus_type_node, &driver_list_);

        probe_buses(drv);
    }

    void add_bus(bus *b)
    {
        scoped_lock g{bus_list_lock_};
        list_add_tail(&b->bus_list_node, &bus_list_);
    }

    template <typename Callable>
    void for_every_bus(Callable cb)
    {
        list_for_every (&bus_list_)
        {
            auto bus = list_head_cpp<struct bus>::self_from_list_head(l);

            if (!cb(bus))
                return;
        }
    }
};

#endif
