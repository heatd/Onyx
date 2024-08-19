/*
 * Copyright (c) 2022 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/mm/slab.h>

#include <onyx/mm/pool.hpp>

memory_pool<slab_cache, MEMORY_POOL_USE_VM> slab_cache_pool;

extern "C" struct slab_cache *slab_cache_alloc()
{
    return slab_cache_pool.allocate(GFP_KERNEL);
}

extern "C" void slab_cache_free(struct slab_cache *c)
{
    slab_cache_pool.free(c);
}
