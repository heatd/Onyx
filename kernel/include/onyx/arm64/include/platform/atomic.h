/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define smp_rmb() __asm__ __volatile__("dmb ishld" ::: "memory")
#define smp_wmb() __asm__ __volatile__("dmb ishst" ::: "memory")
#define smp_mb()  __asm__ __volatile__("dmb ish" ::: "memory")
