/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_RISCV_PLATFORM_VM_H
#define _ONYX_RISCV_PLATFORM_VM_H

struct arch_mm_address_space
{
	void *top_pt;
};

#define vm_get_pgd(arch_mmu)      (arch_mmu)->top_pt
#define vm_set_pgd(arch_mmu, new_pgd) (arch_mmu)->top_pt = new_pgd

void __native_tlb_invalidate_all(void);

#endif
