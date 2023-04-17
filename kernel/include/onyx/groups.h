/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_GROUPS_H
#define _ONYX_GROUPS_H

#include <onyx/refcount.h>
#include <onyx/types.h>
#include <onyx/vector.h>

#include <onyx/utility.hpp>

class supp_groups : public refcountable
{
    cul::vector<gid_t> groups;

public:
    supp_groups() = default;
    ~supp_groups() = default;

    CLASS_DISALLOW_COPY(supp_groups);
    CLASS_DISALLOW_MOVE(supp_groups);

    int set_groups(const gid_t *u_gid_list, size_t size);

    const cul::vector<gid_t> &ids() const
    {
        return groups;
    }

    int get_groups(int size, gid_t *u_gid_list);
};

#endif
