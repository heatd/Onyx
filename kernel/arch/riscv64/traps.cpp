/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/panic.h>
#include <onyx/registers.h>
#include <onyx/riscv/intrinsics.h>

extern "C" void riscv_handle_trap(registers_t *regs)
{
    panic("Exception cause %02x - tp %016x, sp %016x, pc %016x\n", regs->cause, regs->tp, regs->sp,
          regs->epc);
}

extern "C" void riscv_trap_entry();

void riscv_setup_trap_handling()
{
    riscv_write_csr(RISCV_STVEC, (unsigned long) riscv_trap_entry);
}
