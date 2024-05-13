/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_ATOMIC_H
#define _ONYX_ATOMIC_H

#include <platform/atomic.h>

#define READ_ONCE(var)       (__atomic_load_n(&(var), __ATOMIC_RELAXED))
#define WRITE_ONCE(var, val) (__atomic_store_n(&(var), (val), __ATOMIC_RELAXED))

#define atomic_and_relaxed(var, mask) (__atomic_and_fetch(&(var), mask, __ATOMIC_RELAXED))
#define atomic_or_relaxed(var, mask)  (__atomic_or_fetch(&(var), mask, __ATOMIC_RELAXED))

#endif
