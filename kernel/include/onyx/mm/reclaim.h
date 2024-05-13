/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_MM_RECLAIM_H
#define _ONYX_MM_RECLAIM_H

#include <onyx/compiler.h>

#define RECLAIM_MODE_DIRECT     0
#define RECLAIM_MODE_PAGEDAEMON 1

struct reclaim_data
{
    int failed_order;
    int attempt;
    unsigned long nr_reclaimed;
    unsigned int mode;
    unsigned int gfp_flags;
};

__BEGIN_CDECLS

/**
 * @brief Do (direct?) page reclamation. Called from direct reclaim or pagedaemon.
 *
 * @param data Data associated with this reclaim.
 *
 * @return 0 on success, -1 if we failed to go over the high watermark
 */
int page_do_reclaim(struct reclaim_data *data);

__END_CDECLS

#endif
