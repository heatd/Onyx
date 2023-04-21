/*
 * Copyright (c) 2022 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <onyx/intrinsics.h>
#include <onyx/registers.h>
#include <onyx/serial.h>

extern "C" char arm64_exception_vector_table[];

void arm64_setup_trap_handling()
{
    msr("vbar_el1", arm64_exception_vector_table);
    isb();
}

#define DEBUG_BUDGET_PRINTK
#ifdef DEBUG_BUDGET_PRINTK
char buffer[1000];

#define budget_printk(...)                         \
    snprintf(buffer, sizeof(buffer), __VA_ARGS__); \
    platform_serial_write(buffer, strlen(buffer))

#define printk budget_printk
#endif

#define regs_format(regs, esr)                                                                    \
    "Exception at %016lx - ESR %lx\n"                                                             \
    "Registers: \n"                                                                               \
    "x0:  %016lx x1:  %016lx x2:  %016lx\n"                                                       \
    "x3:  %016lx x4:  %016lx x5:  %016lx\n"                                                       \
    "x6:  %016lx x7:  %016lx x8:  %016lx\n"                                                       \
    "x9:  %016lx x10: %016lx x11: %016lx\n"                                                       \
    "x12: %016lx x13: %016lx x14: %016lx\n"                                                       \
    "x15: %016lx x16: %016lx x17: %016lx\n"                                                       \
    "x18: %016lx x19: %016lx x20: %016lx\n"                                                       \
    "x21: %016lx x22: %016lx x23: %016lx\n"                                                       \
    "x24: %016lx x25: %016lx x26: %016lx\n"                                                       \
    "x27: %016lx x28: %016lx x29: %016lx\n"                                                       \
    "x30: %016lx sp:  %016lx pstate: %016lx\n",                                                   \
        (regs)->pc, esr, (regs)->x[0], (regs)->x[1], (regs)->x[2], (regs)->x[3], (regs)->x[4],    \
        (regs)->x[5], (regs)->x[6], (regs)->x[7], (regs)->x[8], (regs)->x[9], (regs)->x[10],      \
        (regs)->x[11], (regs)->x[12], (regs)->x[13], (regs)->x[14], (regs)->x[15], (regs)->x[16], \
        (regs)->x[17], (regs)->x[18], (regs)->x[19], (regs)->x[20], (regs)->x[21], (regs)->x[22], \
        (regs)->x[23], (regs)->x[24], (regs)->x[25], (regs)->x[26], (regs)->x[27], (regs)->x[28], \
        (regs)->x[29], (regs)->x[30], (regs)->sp, (regs)->pstate

void dump_exception_state(struct registers *regs, unsigned long esr)
{
    printk(regs_format(regs, esr));
}

void panic_exception(struct registers *regs, unsigned long esr)
{
    panic(regs_format(regs, esr));
}

extern "C" void arm64_exception_sync(struct registers *regs)
{
    panic_exception(regs, mrs(REG_ESR));
}

extern "C" void arm64_exception_serror(struct registers *regs)
{
    panic_exception(regs, mrs(REG_ESR));
}

extern "C" void arm64_exception_irq(struct registers *regs)
{
    panic_exception(regs, 0);
}

extern "C" void arm64_exception_fiq(struct registers *regs)
{
    panic_exception(regs, 0);
}
