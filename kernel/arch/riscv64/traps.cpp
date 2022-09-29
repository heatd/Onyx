/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/exceptions.h>
#include <onyx/panic.h>
#include <onyx/registers.h>
#include <onyx/riscv/intrinsics.h>
#include <onyx/scheduler.h>
#include <onyx/signal.h>
#include <onyx/softirq.h>
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

#define INSTRUCTION_PAGE_FAULT 12
#define LOAD_PAGE_FAULT        13
#define STORE_PAGE_FAULT       15

bool exception_has_special_handling(unsigned long cause)
{
    switch (cause)
    {
        case INSTRUCTION_PAGE_FAULT:
        case LOAD_PAGE_FAULT:
        case STORE_PAGE_FAULT:
            return true;
    }

    return false;
}

void panic_interrupt_context(registers *ctx)
{
    char tempbuf[40];
    const char *str = nullptr;
    auto num = ctx->cause & ~RISCV_SCAUSE_INTERRUPT;
    if (num < sizeof(exception_msg) / sizeof(exception_msg[0]))
        str = exception_msg[num];

    if (!str)
    {
        snprintf(tempbuf, sizeof(tempbuf), "Unknown exception %lu", num);
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
    info.user = !in_kernel_space_regs(ctx);
    info.ip = ctx->epc;

    if (vm_handle_page_fault(&info) < 0)
    {

        if (!info.user)
        {
            unsigned long fixup;
            if ((fixup = exceptions_get_fixup(info.ip)) != NO_FIXUP_EXISTS)
            {
                ctx->epc = fixup;
                return;
            }
        }

        vm_do_fatal_page_fault(&info);
    }
}

static void instruction_page_fault(registers_t *ctx)
{
    do_page_fault(ctx, PF_X);
}

static void load_page_fault(registers_t *ctx)
{
    do_page_fault(ctx, PF_R);
}

static void store_page_fault(registers_t *ctx)
{
    do_page_fault(ctx, PF_W);
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

long do_syscall64(registers_t *frame);

void riscv_handle_exception(registers_t *regs, unsigned long cause)
{
    // cause 8 is syscall from user-mode
    if (cause == 8)
    {
        irq_enable();
        long ret = do_syscall64(regs);
        regs->a0 = ret;
        regs->epc += 4;
        return;
    }

    if (in_kernel_space_regs(regs) && !exception_has_special_handling(cause))
        panic_interrupt_context(regs);

    // Restore IRQs
    if (regs->status & RISCV_SSTATUS_SPIE)
        irq_enable();

    user_trap_table[cause](regs);
}

static void check_for_resched(registers_t **context)
{
    struct thread *curr = get_current_thread();
    if (curr && sched_needs_resched(curr))
    {
        curr->flags &= ~THREAD_NEEDS_RESCHED;
        *context = (registers_t *) sched_preempt_thread(*context);
    }
}

void riscv_timer_irq();

void riscv_handle_interrupt(registers_t *regs, unsigned long cause)
{
    // IRQs run with interrupts disabled
    const auto flags = irq_save_and_disable();

    if (cause == 5)
    {
        // Supervisor timer interrupt
        riscv_timer_irq();
    }
    else
    {
        panic("external");
    }

    // Run softirqs if we can
    if (!sched_is_preemption_disabled() && softirq_pending())
    {
        softirq_handle();
    }

    irq_restore(flags);
}

extern "C" unsigned long riscv_handle_trap(registers_t *regs)
{
    context_tracking_enter_kernel();

    const auto is_exception = !(regs->cause & RISCV_SCAUSE_INTERRUPT);
    const auto cause = regs->cause & ~RISCV_SCAUSE_INTERRUPT;

    if (is_exception)
        riscv_handle_exception(regs, cause);
    else
        riscv_handle_interrupt(regs, cause);

    context_tracking_exit_kernel();

    if (regs->status & RISCV_SSTATUS_SPIE && !sched_is_preemption_disabled())
    {
        // If preemption is enabled and interrupts are enabled, try to do a resched
        check_for_resched(&regs);
    }

    if (signal_is_pending())
        handle_signal(regs);

    return (unsigned long) regs;
}

extern "C" void riscv_trap_entry();

void riscv_setup_trap_handling()
{
    riscv_write_csr(RISCV_STVEC, (unsigned long) riscv_trap_entry);
}
