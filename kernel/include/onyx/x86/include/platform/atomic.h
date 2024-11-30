/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define smp_wmb() __asm__ __volatile__("" ::: "memory")
#define smp_rmb() __asm__ __volatile__("" ::: "memory")
#define smp_mb()  __asm__ __volatile__("lock addl $0, -4(%%rsp)" ::: "memory", "cc")
