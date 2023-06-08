/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include "ktsan.h"

extern "C" __init void __tsan_init()
{
    kt_init_sync_cache();
    kt_init_thread_ht();
}
