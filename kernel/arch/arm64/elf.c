/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <assert.h>
#include <string.h>

#include <onyx/process.h>
#include <onyx/registers.h>

#include <uapi/user.h>

void core_fill_regs(elf_gregset_t *set, struct process *thread)
{
    /* thread is alive and suspended (or is us. either way, task_regs will work ) */
    struct registers *regs = task_regs(thread);
    /* struct register layout = elf_gregset_t layout */
    static_assert(sizeof(*regs) == sizeof(*set),
                  "arm64 struct register layout must be similar to elf_gregset_t");
    memcpy(set, regs, sizeof(*regs));
}
