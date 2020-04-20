/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_X86_VM_H
#define _ONYX_X86_VM_H

struct arch_mm_address_space
{
	void *cr3;
};

#define vm_get_pgd(arch_mmu)      (arch_mmu)->cr3
#define vm_set_pgd(arch_mmu, new_pgd) (arch_mmu)->cr3 = new_pgd

#endif
