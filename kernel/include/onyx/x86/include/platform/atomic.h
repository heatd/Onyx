/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#define smp_wmb() __asm__ __volatile__("" ::: "memory")
#define smp_rmb() __asm__ __volatile__("" ::: "memory")
#define smp_mb()  __asm__ __volatile__("mfence" ::: "memory")
