/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_RMAP_H
#define _ONYX_RMAP_H

#include <onyx/list.h>
#include <onyx/spinlock.h>

struct vm_area_struct;

struct anon_vma
{
    struct spinlock lock;
    struct list_head vma_list;
};
__BEGIN_CDECLS

struct anon_vma *anon_vma_alloc(void);
void __anon_vma_unlink(struct anon_vma *anon, struct vm_area_struct *vma);
void anon_vma_unlink(struct anon_vma *anon, struct vm_area_struct *vma);
void __anon_vma_link(struct anon_vma *anon, struct vm_area_struct *vma);
void anon_vma_link(struct anon_vma *anon, struct vm_area_struct *vma);
struct anon_vma *anon_vma_prepare(struct vm_area_struct *vma);

long rmap_get_page_references(struct page *page, unsigned int *vm_flags);

int rmap_try_to_unmap(struct page *page);

__END_CDECLS
#endif
