/*
 * Copyright (c) 2019 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _CARBON_X86_EFLAGS_H
#define _CARBON_X86_EFLAGS_H

#define EFLAGS_CARRY           (1 << 0)
#define EFLAGS_RESV0           (1 << 1)
#define EFLAGS_PARITY          (1 << 2)
#define EFLAGS_ADJUST          (1 << 4)
#define EFLAGS_ZERO            (1 << 6)
#define EFLAGS_SIGN            (1 << 7)
#define EFLAGS_TRAP            (1 << 8)
#define EFLAGS_INT_ENABLED     (1 << 9)
#define EFLAGS_DIRECTION       (1 << 10)
#define EFLAGS_OVERFLOW        (1 << 11)
#define EFLAGS_ALIGNMENT_CHECK (1 << 18)

#ifdef __cplusplus

static constexpr unsigned long default_rflags = EFLAGS_INT_ENABLED | EFLAGS_RESV0;

#endif

#endif
