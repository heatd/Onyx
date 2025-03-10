/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef ONYX_RISCV_INCLUDE_PLATFORM_ELF_H
#define ONYX_RISCV_INCLUDE_PLATFORM_ELF_H

#include <onyx/compiler.h>
#include <onyx/elf.h>

#include <uapi/user.h>

#define EM_CURRENT EM_RISCV

static inline int arch_elf_do_rela(unsigned long addr, const Elf64_Rela *rela, unsigned long sym,
                                   unsigned long type)
{
    return -1;
}

__BEGIN_CDECLS
void core_fill_regs(elf_gregset_t *set, struct process *thread);
__END_CDECLS

#endif
