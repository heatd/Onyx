/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <onyx/page_frag.h>

static int page_frag_refill(struct page_frag_info *pfi, unsigned int len, gfp_t gfp)
{
    unsigned int order = pages2order(vm_size_to_pages(len));

    if (WARN_ON_ONCE(order > 0))
    {
        /* TODO: We're missing GFP_COMP support, and without it the refcounting gets all screwed
         * up. So reject order > 0 allocations. */
        pr_warn("%s: Asked for %u bytes, which we can't deliver\n", __func__, len);
        return -ENOMEM;
    }

    if (pfi->page)
        page_unref(pfi->page);

    pfi->page = alloc_pages(order, gfp);
    if (!pfi->page)
        return -ENOMEM;
    pfi->offset = 0;
    pfi->len = 1UL << (order + PAGE_SHIFT);
    return 0;
}

int page_frag_alloc(struct page_frag_info *pfi, unsigned int len, gfp_t gfp, struct page_frag *frag)
{
    /* Check if we don't have a page already, or if we dont have enough space for the frag */
    if (!pfi->page || pfi->len - pfi->offset < len)
    {
        if (page_frag_refill(pfi, len, gfp) < 0)
            return -ENOMEM;
    }

    page_ref(pfi->page);
    frag->page = pfi->page;
    frag->len = len;
    frag->offset = pfi->offset;
    pfi->offset += len;

    if (pfi->offset == len)
    {
        /* Release our ref if someone ate the whole thing. */
        page_unref(pfi->page);
        pfi->page = NULL;
    }

    return 0;
}

void pfi_destroy(struct page_frag_info *pfi)
{
    if (pfi->page)
        page_unref(pfi->page);
}
