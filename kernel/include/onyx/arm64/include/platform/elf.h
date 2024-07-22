/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef ONYX_ARM64_INCLUDE_PLATFORM_ELF_H
#define ONYX_ARM64_INCLUDE_PLATFORM_ELF_H

#include <onyx/elf.h>

#define EM_CURRENT EM_AARCH64

static inline int arch_elf_do_rela(unsigned long addr, const Elf64_Rela *rela, unsigned long sym,
                                   unsigned long type)
{
    return -1;
}

#endif
