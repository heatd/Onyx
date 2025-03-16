/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_VMA_INTERNAL_H
#define _ONYX_VMA_INTERNAL_H

#include <onyx/maple_tree.h>
#include <onyx/mm_address_space.h>

struct vma_iterator
{
    unsigned long index;
    unsigned long end;
    struct mm_address_space *mm;
    struct ma_state mas;
};

#define VMA_ITERATOR(name, mm, index, end)           \
    struct vma_iterator name = {index, (end) -1, mm, \
                                MA_STATE_INIT(&(mm)->region_tree, index, (end) -1)}

static inline void vmi_init(struct vma_iterator *vmi, struct mm_address_space *mm,
                            unsigned long index, unsigned long end)
{
    vmi->index = index;
    vmi->end = end - 1;
    vmi->mm = mm;
    mas_init(&vmi->mas, &mm->region_tree, index);
}

static inline void vmi_destroy(struct vma_iterator *vmi)
{
    mas_destroy(&vmi->mas);
}

struct vm_area_struct *vma_prepare_modify(struct vma_iterator *vmi, struct vm_area_struct *vma,
                                          unsigned long start, unsigned long end);
#endif
