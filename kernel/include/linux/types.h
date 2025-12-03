/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

#include <onyx/types.h>
// #include <onyx/rcuwait_types.h>
#include <asm-generic/bitsperlong.h>

typedef s64 ktime_t;

typedef struct {
	int counter;
} atomic_t;

#define ATOMIC_INIT(i) { (i) }

typedef struct {
	s64 counter;
} atomic64_t;

struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct hlist_head {
	struct hlist_node *first;
};

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define BITS_TO_LONGS(bits) __KERNEL_DIV_ROUND_UP(bits, BITS_PER_LONG)

#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]


typedef off_t loff_t;

#endif
