/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_ASSERT_H
#define _ONYX_ASSERT_H

#include <assert.h>

#define CHECK(x) assert(x)

// TODO(heat): make this dependent on CONFIG_DEBUG or so
#define DCHECK(x) assert(x)

#endif
