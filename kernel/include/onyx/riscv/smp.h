/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_RISCV_SMP_H
#define _ONYX_RISCV_SMP_H

#include <onyx/types.h>

#define RISCV_IPI_TYPE_SYNC_CALL (1 << 0)
#define RISCV_IPI_TYPE_RESCHED   (1 << 1)

namespace riscv
{

u32 get_pending_ipi();

}

#endif
