/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/intrinsics.h>

extern "C" char arm64_exception_vector_table[];

void arm64_setup_trap_handling()
{
    msr("vbar_el1", arm64_exception_vector_table);
}
