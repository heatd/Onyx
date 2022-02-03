/*
 * Copyright (c) 2018 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>

#include <onyx/disassembler.h>
#include <onyx/registers.h>

__attribute__((no_sanitize_undefined)) int debug_opcode(uint8_t *pc, struct registers *ctx)
{
    switch (*pc)
    {
    case 0xe8: {
        uintptr_t *off = (uintptr_t *) (pc + 1);
        uintptr_t target_rip = (*off) + (uintptr_t) pc + 5;
        printk("calling %p from %lx\n", pc, target_rip);
        break;
    }
    case 0xc3: {
        printk("returning to %lx\n", *(uintptr_t *) ctx->rsp);
        break;
    }
    }
    return 0;
}
