/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_SWAP_H
#define _ONYX_SWAP_H

#include <stdbool.h>

#include <onyx/compiler.h>
#include <onyx/pgtable.h>

__BEGIN_CDECLS
/**
 * @brief Check if indeed we have some swap space available
 * This function is not precise and may return false negatives/positives.
 * Used by page reclaim code to avoid anon page reclaim when no swap is available
 *
 * @return True if it _looks_ like swap is available, else false
 */
bool swap_is_available(void);

/**
 * @brief Add a page to swap
 *
 * Add a page to swap (and the swap cache) and set PAGE_FLAG_SWAP.
 * @param page Page to start swapping out
 * @return 0 on success, negative error numbers
 */
int swap_add(struct page *page);

struct vm_object;
extern struct vm_object *swap_spaces[];

struct vm_pf_context;
int do_swap_page(struct vm_pf_context *context);

void __swap_inc_map(swp_entry_t swp);
void swap_inc_map(struct page *page);
void swap_unset_swapcache(swp_entry_t swp);
bool swap_put(swp_entry_t entry);

__END_CDECLS

#endif
