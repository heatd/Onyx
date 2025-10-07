/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/arm64/mmu.h>
#include <onyx/page.h>
#include <onyx/pgtable.h>

#define _PAGE_ANY       (ARM64_MMU_INNER_SHAREABLE | MMU_PTR_ATTR_NORMAL_MEMORY | ARM64_MMU_PAGE)
#define _PAGE_KERNELPTE (_PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_ANY)
#define _PAGE_USERPTE   (_PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_USER | _PAGE_ANY | ARM64_MMU_nG)

const pgprotval_t arm64_pgprot[ARM64_MAX_NR_PGPROT] = {
    [0] = _PAGE_PROTNONE | _PAGE_ANY,
    [VM_READ] = _PAGE_KERNELPTE | _PAGE_READONLY | _PAGE_NX,
    [VM_WRITE] = _PAGE_KERNELPTE | _PAGE_NX,
    [VM_READ | VM_WRITE] = _PAGE_KERNELPTE | _PAGE_NX,
    [VM_EXEC] = _PAGE_KERNELPTE | _PAGE_READONLY,
    [VM_READ | VM_EXEC] = _PAGE_KERNELPTE | _PAGE_READONLY,
    [VM_WRITE | VM_EXEC] = _PAGE_KERNELPTE,
    [VM_READ | VM_WRITE | VM_EXEC] = _PAGE_KERNELPTE,
    /* User PTEs now */
    [0 | VM_USER] = _PAGE_PROTNONE | _PAGE_ANY,
    [VM_READ | VM_USER] = _PAGE_USERPTE | _PAGE_READONLY | _PAGE_NX,
    [VM_WRITE | VM_USER] = _PAGE_USERPTE | _PAGE_NX,
    [VM_READ | VM_WRITE | VM_USER] = _PAGE_USERPTE | _PAGE_NX,
    [VM_EXEC | VM_USER] = _PAGE_USERPTE | _PAGE_READONLY,
    [VM_READ | VM_EXEC | VM_USER] = _PAGE_USERPTE | _PAGE_READONLY,
    [VM_WRITE | VM_EXEC | VM_USER] = _PAGE_USERPTE,
    [VM_READ | VM_WRITE | VM_EXEC | VM_USER] = _PAGE_USERPTE,
};
