/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_MM_SHRINKER_H
#define _ONYX_MM_SHRINKER_H

#include <onyx/list.h>

struct shrink_control
{
    /**
     * @brief Target of objects to free. In scan_objects, it's given as number of pages, and
     * scan_objects adjusts it to an aproximate number of objects.
     */
    unsigned long target_objs;
    unsigned long nr_freed;
    unsigned int gfp_flags;
};

#define SHRINK_STOP 1

struct shrinker
{
    const char *name;
    unsigned long flags;
    int (*scan_objects)(struct shrinker *s, struct shrink_control *ctl);
    int (*shrink_objects)(struct shrinker *s, struct shrink_control *ctl);
    struct list_head list_node;
};

/**
 * @brief Is a cache of objects that need IO or are costly to reconstruct.
 *
 */
#define SHRINKER_NEEDS_IO (1 << 0)

void shrinker_register(struct shrinker *shr);
void shrinker_unregister(struct shrinker *shr);

#endif
