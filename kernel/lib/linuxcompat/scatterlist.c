/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/mm/slab.h>

#include <linux/scatterlist.h>

#define MAX_SCATTERLIST_CONTIG (PAGE_SIZE / sizeof(struct scatterlist))

int sg_alloc_table(struct sg_table *table, unsigned int nents, gfp_t gfp)
{
    struct scatterlist *sg, *prev = NULL;
    unsigned int curr_ents;

    table->sgl = NULL;
    table->orig_nents = 0;
    table->nents = 0;

    while (nents > 0)
    {
        curr_ents = min(nents, MAX_SCATTERLIST_CONTIG);
        sg = kcalloc(curr_ents, sizeof(struct scatterlist), gfp);
        if (!sg)
            goto enomem;
        sg_end(&sg[curr_ents - 1]);

        if (!table->sgl)
            table->sgl = sg;

        if (nents - curr_ents > 0)
        {
            /* We'll need to allocate more, so disregard the last entry */
            curr_ents--;
        }

        table->nents += curr_ents;
        table->orig_nents += curr_ents;
        if (prev)
        {
            /* Need to chain with previous */
            sg_chain(prev, MAX_SCATTERLIST_CONTIG, sg);
        }

        prev = sg;
        nents -= curr_ents;
    }

    return 0;
enomem:
    sg_free_table(table);
    return -ENOMEM;
}

void sg_free_table(struct sg_table *table)
{
    struct scatterlist *sg, *next;
    unsigned int curr_ents;

    sg = table->sgl;
    next = NULL;
    while (table->orig_nents > 0)
    {
        curr_ents = min(table->orig_nents, MAX_SCATTERLIST_CONTIG);
        if (table->orig_nents > MAX_SCATTERLIST_CONTIG)
        {
            /* We have a chain, certainly */
            next = sg_chain_ptr(sg + MAX_SCATTERLIST_CONTIG - 1);
            curr_ents--;
        }
        else
            next = NULL;

        kfree(sg);
        sg = next;
        next = NULL;
        table->orig_nents -= curr_ents;
    }

    table->sgl = NULL;
    WARN_ON(table->orig_nents != 0);
    table->nents = 0;
}
