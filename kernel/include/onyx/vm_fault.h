/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_VM_FAULT_H
#define _ONYX_VM_FAULT_H

#include <onyx/pgtable.h>

struct vm_area_struct;
struct fault_info;

struct vm_pf_context
{
    /* The vm area in question */
    struct vm_area_struct *entry;
    /* This fault's info */
    struct fault_info *info;
    /* vpage - fault_address but page aligned */
    unsigned long vpage;
    /* Page permissions - is prefilled by calling code */
    int page_rwx;
    /* Mapping info if page was present */
    unsigned long mapping_info;
    pte_t oldpte;
    pmd_t oldpmd;
    /* The to-be-mapped page - filled by called code */
    struct page *page;
    pmd_t *pmd;
};

#endif
