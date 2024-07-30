/*
 * Copyright (c) 2022 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_ASSERT_H
#define _ONYX_ASSERT_H

#include <assert.h>

#define CHECK(x) assert(x)

#ifdef CONFIG_DCHECK
#define DCHECK(x) assert(x)
#else
/* Use __builtin_constant_p to discard unused warnings, while not evaluating the expression. */
#define DCHECK(x) ((void) __builtin_constant_p((x)))
#endif

#endif
