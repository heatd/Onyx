/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PGTABLE_NOP4D_H
#define _ONYX_PGTABLE_NOP4D_H

#define PTRS_PER_P4D 1

static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long addr)
{
    return (p4d_t *) pgd;
}

static inline bool pgd_none(pgd_t pgd)
{
    return false;
}

static inline bool pgd_present(pgd_t pgd)
{
    return true;
}

static inline bool p4d_folded(void)
{
    return true;
}

#endif
