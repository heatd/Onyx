/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_WAIT_H
#define _ONYX_WAIT_H

#include <stdint.h>

#include <onyx/timer.h>

#define WAIT_FOR_SIZE(x)   (x)
#define WAIT_FOR_SIZE_MASK 0xf

#define WAIT_FOR_FOREVER            (1 << 4)
#define WAIT_FOR_MATCHES_EVERYTHING (1 << 5)

unsigned long wake_address(void *ptr);
int wait_for_mask(void *val, uint64_t mask, unsigned int flags, hrtime_t timeout);
int wait_for(void *ptr, bool (*complete)(void *), unsigned int flags, hrtime_t timeout);

#endif
