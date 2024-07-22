/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_ARM64_PLATFORM_VM_H
#define _ONYX_ARM64_PLATFORM_VM_H

#include <onyx/types.h>

struct arch_mm_address_space
{
    void *top_pt;
};

#define vm_get_pgd(arch_mmu)          (arch_mmu)->top_pt
#define vm_set_pgd(arch_mmu, new_pgd) (arch_mmu)->top_pt = new_pgd

void __native_tlb_invalidate_all(void);

/**
 * @brief Interpret mmap's hint and flags in an architecture-dependent way
 *
 * @param hint Hint passed to mmap (but sanitized!)
 * @param flags Flags given to mmap (but sanitized!)
 * @return Extra flags
 */
static inline u64 arch_vm_interpret_mmap_hint_flags(void *hint, int flags)
{
    return 0;
}

static inline bool arch_vm_validate_mmap_region(unsigned long start, unsigned long size, u64 flags)
{
    return true;
}

#endif
