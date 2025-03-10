/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef ONYX_X86_INCLUDE_PLATFORM_ELF_H
#define ONYX_X86_INCLUDE_PLATFORM_ELF_H

#include <onyx/cpu.h>
#include <onyx/elf.h>

#include <uapi/user.h>

#define EM_CURRENT EM_X86_64

#define EM_CURRENT_COMPAT EM_386

static inline int arch_elf_do_rela(unsigned long addr, const Elf64_Rela *rela, unsigned long sym,
                                   unsigned long type)
{
    uintptr_t *p = (uintptr_t *) (addr + rela->r_offset);
    int32_t *ptr32s = (int32_t *) p;
    uint32_t *ptr32u = (uint32_t *) p;

    switch (type)
    {
        case R_X86_64_NONE:
            break;
        case R_X86_64_64:
            *p = RELOCATE_R_X86_64_64(sym, rela->r_addend);
            break;
        case R_X86_64_32S:
            *ptr32s = RELOCATE_R_X86_64_32S(sym, rela->r_addend);
            break;
        case R_X86_64_32:
            *ptr32u = RELOCATE_R_X86_64_32(sym, rela->r_addend);
            break;
        case R_X86_64_PC32:
        case R_X86_64_PLT32:
            *ptr32u = RELOCATE_R_X86_64_PC32(sym, rela->r_addend, (uintptr_t) p);
            break;
        default:
            return -1;
    }

    return 0;
}

#define ELF_HWCAP (bootcpu_info.caps[0])

__BEGIN_CDECLS
void core_fill_regs(elf_gregset_t *set, struct process *thread);
__END_CDECLS
#endif
