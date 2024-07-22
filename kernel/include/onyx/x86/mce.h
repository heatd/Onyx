/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_X86_MCE_H
#define _ONYX_X86_MCE_H

#include <onyx/registers.h>

void do_machine_check(struct registers *ctx);

#endif
