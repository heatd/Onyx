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
#include <onyx/scheduler.h>
#include <onyx/signal.h>
#include <onyx/vm.h>

static const char *exception_msg[] = {
    "Instruction address misaligned",
    "Instruction access fault",
    "Illegal instruction",
    "Breakpoint",
    "Load address misaligned",
    "Load access fault",
    "Store address misaligned",
    "Store access fault",
    "Environment call from U-mode",
    "Environment call from S-mode",
    nullptr,
    nullptr,
    "Instruction page fault",
    "Load page fault",
    nullptr,
    "Store page fault",
};

void panic_interrupt_context(registers *ctx)
{
    char tempbuf[40];
    const char *str = nullptr;
    auto num = ctx->cause & ~RISCV_SCAUSE_INTERRUPT;
    if (num < sizeof(exception_msg) / sizeof(exception_msg[0]))
        str = exception_msg[num];

    if (!str)
    {
        snprintf(tempbuf, sizeof(tempbuf), "Unknown exception %u", num);
        str = tempbuf;
    }

    panic("Trap: %s at %016lx\n"
          "Registers: \n"
          "ra: %016lx sp:  %016lx gp: %016lx\n"
          "tp: %016lx t0:  %016lx t1: %016lx\n"
          "t2: %016lx fp:  %016lx s1: %016lx\n"
          "a0: %016lx a1:  %016lx a2: %016lx\n"
          "a3: %016lx a4:  %016lx a5: %016lx\n"
          "a6: %016lx a7:  %016lx s2: %016lx\n"
          "s3: %016lx s4:  %016lx s5: %016lx\n"
          "s6: %016lx s7:  %016lx s8: %016lx\n"
          "s9: %016lx s10: %016lx s11: %016lx\n"
          "t3: %016lx t4:  %016lx t5:  %016lx\n"
          "t6: %016lx\n"
          "scause: %016lx stval: %016lx sstatus: %016lx\n",
          str, ctx->epc, ctx->gpr[0], ctx->gpr[1], ctx->gpr[2], ctx->gpr[3], ctx->gpr[4],
          ctx->gpr[5], ctx->gpr[6], ctx->gpr[7], ctx->gpr[8], ctx->gpr[9], ctx->gpr[10],
          ctx->gpr[11], ctx->gpr[12], ctx->gpr[13], ctx->gpr[14], ctx->gpr[15], ctx->gpr[16],
          ctx->gpr[17], ctx->gpr[18], ctx->gpr[19], ctx->gpr[20], ctx->gpr[21], ctx->gpr[22],
          ctx->gpr[23], ctx->gpr[24], ctx->gpr[25], ctx->gpr[26], ctx->gpr[27], ctx->gpr[28],
          ctx->gpr[29], ctx->gpr[30], ctx->cause, ctx->tval, ctx->status);
}

static void instruction_address_misaligned(registers_t *ctx)
{
    siginfo_t info = {};
    info.si_code = BUS_ADRALN;
    info.si_addr = (void *) ctx->tval;

    kernel_tkill(SIGBUS, get_current_thread(), SIGNAL_FORCE, &info);
}

static void instruction_access_fault(registers_t *ctx)
{
    siginfo_t info = {};
    info.si_code = BUS_ADRERR;
    info.si_addr = (void *) ctx->tval;

    kernel_tkill(SIGBUS, get_current_thread(), SIGNAL_FORCE, &info);
}

static void illegal_instruction(registers_t *ctx)
{
    siginfo_t info = {};
    info.si_code = ILL_ILLOPC;
    info.si_addr = (void *) ctx->tval;

    kernel_tkill(SIGILL, get_current_thread(), SIGNAL_FORCE, &info);
}

static void breakpoint_trap(registers_t *ctx)
{
    siginfo_t info = {};
    info.si_code = TRAP_BRKPT;

    kernel_tkill(SIGTRAP, get_current_thread(), SIGNAL_FORCE, &info);
}

static void load_address_misaligned(registers_t *ctx)
{
    siginfo_t info = {};
    info.si_code = BUS_ADRALN;
    info.si_addr = (void *) ctx->tval;

    kernel_tkill(SIGBUS, get_current_thread(), SIGNAL_FORCE, &info);
}

static void load_access_fault(registers_t *ctx)
{
    siginfo_t info = {};
    info.si_code = BUS_ADRERR;
    info.si_addr = (void *) ctx->tval;

    kernel_tkill(SIGBUS, get_current_thread(), SIGNAL_FORCE, &info);
}

static void store_address_misaligned(registers_t *ctx)
{
    siginfo_t info = {};
    info.si_code = BUS_ADRALN;
    info.si_addr = (void *) ctx->tval;

    kernel_tkill(SIGBUS, get_current_thread(), SIGNAL_FORCE, &info);
}

static void store_access_fault(registers_t *ctx)
{
    siginfo_t info = {};
    info.si_code = BUS_ADRERR;
    info.si_addr = (void *) ctx->tval;

    kernel_tkill(SIGBUS, get_current_thread(), SIGNAL_FORCE, &info);
}

#define PF_R (1 << 0)
#define PF_W (1 << 1)
#define PF_X (1 << 2)

static void do_page_fault(registers_t *ctx, unsigned long pf_flags)
{
    uintptr_t fault_address = ctx->tval;

    struct fault_info info;
    info.signal = VM_SIGSEGV;
    info.fault_address = fault_address;
    info.write = pf_flags & PF_W;
    info.read = pf_flags & PF_R;
    info.exec = pf_flags & PF_X;
    info.user = in_kernel_space_regs(ctx);
    info.ip = ctx->epc;

    if (vm_handle_page_fault(&info) < 0)
    {
#if 0
        if (!info.user)
        {
            unsigned long fixup;
            if ((fixup = exceptions_get_fixup(info.ip)) != NO_FIXUP_EXISTS)
            {
                ctx->rip = fixup;
                return;
            }
        }
#endif

        vm_do_fatal_page_fault(&info);
    }
}

static void instruction_page_fault(registers_t *ctx)
{
    do_page_fault(ctx, PF_X);
}

static void load_page_fault(registers_t *ctx)
{
    do_page_fault(ctx, PF_X);
}

static void store_page_fault(registers_t *ctx)
{
    do_page_fault(ctx, PF_X);
}

void (*const user_trap_table[])(registers *ctx) = {instruction_address_misaligned,
                                                   instruction_access_fault,
                                                   illegal_instruction,
                                                   breakpoint_trap,
                                                   load_address_misaligned,
                                                   load_access_fault,
                                                   store_address_misaligned,
                                                   store_access_fault,
                                                   panic_interrupt_context,
                                                   panic_interrupt_context,
                                                   panic_interrupt_context,
                                                   panic_interrupt_context,
                                                   instruction_page_fault,
                                                   load_page_fault,
                                                   panic_interrupt_context,
                                                   store_page_fault};

extern "C" void riscv_handle_trap(registers_t *regs)
{
    auto is_exception = !(regs->cause & RISCV_SCAUSE_INTERRUPT);

    if (is_exception && in_kernel_space_regs(regs))
        panic_interrupt_context(regs);

    user_trap_table[regs->cause & ~RISCV_SCAUSE_INTERRUPT](regs);
}

extern "C" void riscv_trap_entry();

void riscv_setup_trap_handling()
{
    riscv_write_csr(RISCV_STVEC, (unsigned long) riscv_trap_entry);
}
