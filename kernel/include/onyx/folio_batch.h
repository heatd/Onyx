/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_FOLIO_BATCH_H
#define _ONYX_FOLIO_BATCH_H

#include <onyx/page.h>

struct folio_batch
{
    unsigned int nr;
    struct folio *batch[31];
};

static inline void folio_batch_init(struct folio_batch *batch)
{
    batch->nr = 31;
}

static unsigned int folio_batch_add(struct folio_batch *batch, struct folio *folio)
{
    folio_get(folio);
    batch->batch[batch->nr++] = folio;
    return batch->nr - 31;
}

static void folio_end_batch(struct folio_batch *batch)
{
    /* No locks should be held. Puts pages and clears the batch */
    for (unsigned int i = 0; i < batch->nr; i++)
        folio_put(batch->batch[i]);
    batch->nr = 0;
}

static inline unsigned int folio_batch_count(struct folio_batch *batch)
{
    return batch->nr - 31;
}

#endif
