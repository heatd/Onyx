/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include "ktsan.h"

#include <onyx/utility.hpp>

void kt_clk_acquire(kt_clock *dest, kt_clock *src)
{
    for (unsigned long i = 0; i < KTSAN_MAX_THREADS; i++)
        dest->time[i] = cul::max(dest->time[i], src->time[i]);
}

void kt_clk_set(kt_clock *dest, kt_clock *src)
{
    for (unsigned long i = 0; i < KTSAN_MAX_THREADS; i++)
        dest->time[i] = src->time[i];
}
