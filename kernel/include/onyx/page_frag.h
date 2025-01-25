/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PAGE_FRAG_H
#define _ONYX_PAGE_FRAG_H

#include <onyx/compiler.h>
#include <onyx/page.h>

__BEGIN_CDECLS

struct page_frag_info
{
    struct page *page;
    unsigned int offset;
    unsigned int len;
};

struct page_frag
{
    struct page *page;
    unsigned int offset;
    unsigned int len;
};

static inline void pfi_init(struct page_frag_info *pfi)
{
    pfi->page = NULL;
    pfi->len = pfi->offset = 0;
}

int page_frag_alloc(struct page_frag_info *pfi, unsigned int len, gfp_t gfp,
                    struct page_frag *frag);

void pfi_destroy(struct page_frag_info *pfi);

__END_CDECLS

#endif
