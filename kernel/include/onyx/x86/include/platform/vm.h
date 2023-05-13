/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_X86_VM_H
#define _ONYX_X86_VM_H

#include <onyx/types.h>

struct arch_mm_address_space
{
    void *cr3{nullptr};
};

#define vm_get_pgd(arch_mmu)          (arch_mmu)->cr3
#define vm_set_pgd(arch_mmu, new_pgd) (arch_mmu)->cr3 = new_pgd

void __native_tlb_invalidate_all();

void x86_remap_top_pgd_to_top_pgd(unsigned long source, unsigned long dest);

/**
 * @brief Interpret mmap's hint and flags in an architecture-dependent way
 *
 * @param hint Hint passed to mmap (but sanitized!)
 * @param flags Flags given to mmap (but sanitized!)
 * @return Extra flags
 */
u64 arch_vm_interpret_mmap_hint_flags(void *hint, int flags);

bool arch_vm_validate_mmap_region(unsigned long start, unsigned long size, u64 flags);
#endif
