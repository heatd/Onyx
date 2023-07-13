/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>

#include <onyx/exceptions.h>
#include <onyx/intrinsics.h>
#include <onyx/process.h>
#include <onyx/registers.h>
#include <onyx/serial.h>
#include <onyx/vm.h>

extern "C" char arm64_exception_vector_table[];

void arm64_setup_trap_handling()
{
    msr("vbar_el1", arm64_exception_vector_table);
    isb();
}

#define ESR_EC_CLASS(esr) ((esr) & (0b111111U << 26))

#define ESR_EC_UNKNOWN_REASON            0
#define ESR_EC_BREAKPOINT                (0b111100U << 26)
#define ESR_EC_DATA_ABORT                (0b100100U << 26)
#define ESR_EC_INSN_ABORT                (0b100000U << 26)
#define ESR_INSN_DATA_ABORT_NO_EL_CHANGE (1U << 26)
#define ESR_EC_SVC_AA64                  (0b010101U << 26)
#define ESR_EC_TRAP_SYS_REG              (0b011000U << 26)

#undef DEBUG_BUDGET_PRINTK
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

#define DATA_ABORT_WNR (1U << 6)

static void page_fault(struct registers *regs, unsigned long esr)
{
    uintptr_t fault_address = mrs("far_el1");

    // IRQ restores need to be deferred after we collect all the state associated with the fault
    // namely, FAR_EL1.
    irq_restore(regs->pstate);

    bool write = false;
    bool read = false;
    bool exec = false;

    if ((ESR_EC_CLASS(esr) & ~ESR_INSN_DATA_ABORT_NO_EL_CHANGE) == ESR_EC_DATA_ABORT)
    {
        write = esr & DATA_ABORT_WNR;
        read = !write;
    }
    else
    {
        // instruction fault
        exec = true;
    }

    struct fault_info info;
    info.signal = VM_SIGSEGV;
    info.fault_address = fault_address;
    info.write = write;
    info.read = read;
    info.exec = exec;
    info.user = !(esr & ESR_INSN_DATA_ABORT_NO_EL_CHANGE);
    info.ip = regs->pc;
    info.error_info = 0;

    if (vm_handle_page_fault(&info) < 0)
    {
        if (!info.user)
        {
            unsigned long fixup;
            if ((fixup = exceptions_get_fixup(info.ip)) != NO_FIXUP_EXISTS)
            {
                regs->pc = fixup;
                return;
            }
        }

        vm_do_fatal_page_fault(&info);
    }
}

long do_syscall64(registers_t *frame);

static void do_system_call(struct registers *regs)
{
    regs->x[0] = do_syscall64(regs);
}

static void unknown_reason_exception(struct registers *regs)
{
    siginfo_t info = {};
    info.si_code = ILL_ILLOPC;
    info.si_addr = (void *) regs->pc;

    kernel_raise_signal(SIGILL, get_current_process(), SIGNAL_FORCE, &info);
}

#define TRAP_SYS_OP0(x) (((x) >> 20) & 3)
#define TRAP_SYS_OP2(x) ((x) >> 17) & 7)
#define TRAP_SYS_OP1(x) ((x) >> 14) & 7)
#define TRAP_SYS_CRn(x) ((x) >> 10) & 0xf)
#define TRAP_SYS_Rt(x) ((x) >> 5) & 0x1f)
#define TRAP_SYS_CRm(x) ((x) >> 1) & 0x1f)
#define TRAP_SYS_DIR(x) (x & 1)

static void trap_sys_exception(struct registers *regs)
{
    /* TODO: Maybe decompose the ISS as specified in "ISS encoding for an exception from MSR, MRS,
     * or System instruction execution in AArch64 state". Macros above. */
    siginfo_t info = {};
    info.si_code = ILL_PRVREG;
    info.si_addr = (void *) regs->pc;
    unsigned long esr = mrs(REG_ESR);

    printf("trap: MSR/MRS/system exception ESR %08lx on process %s (pid %d)\n", esr,
           get_current_process()->name.data(), get_current_process()->pid_);

    kernel_raise_signal(SIGILL, get_current_process(), SIGNAL_FORCE, &info);
}

static void breakpoint_exception(registers_t *ctx)
{
    siginfo_t info = {};
    info.si_code = TRAP_BRKPT;

    kernel_tkill(SIGTRAP, get_current_thread(), SIGNAL_FORCE, &info);
}

extern "C" void arm64_exception_sync(struct registers *regs)
{
    unsigned long esr = mrs(REG_ESR);
    const auto eclass = ESR_EC_CLASS(esr);

    if (in_kernel_space_regs(regs))
    {
        if (eclass != (ESR_EC_DATA_ABORT | ESR_INSN_DATA_ABORT_NO_EL_CHANGE))
        {
            // If we cannot handle this fault with exception handlers (atm, data abort only)
            // just panic.
            panic_exception(regs, esr);
        }
    }

    // Re-enable irqs
    switch (eclass)
    {
        case ESR_EC_DATA_ABORT:
        case ESR_EC_INSN_ABORT:
        case ESR_EC_DATA_ABORT | ESR_INSN_DATA_ABORT_NO_EL_CHANGE:
        case ESR_EC_INSN_ABORT | ESR_INSN_DATA_ABORT_NO_EL_CHANGE:
            // Ugh, annoying... We must not re-enable irqs for page faults because they'll still
            // grab FAR
            // TODO(pedro): Related to the signals ESR and fault_address TODO
            break;
        default:
            irq_restore(regs->pstate);
    }

    switch (eclass)
    {
        case ESR_EC_DATA_ABORT:
        case ESR_EC_INSN_ABORT:
        case ESR_EC_DATA_ABORT | ESR_INSN_DATA_ABORT_NO_EL_CHANGE:
        case ESR_EC_INSN_ABORT | ESR_INSN_DATA_ABORT_NO_EL_CHANGE:
            page_fault(regs, esr);
            break;
        case ESR_EC_SVC_AA64:
            // dump_exception_state(regs, esr);
            do_system_call(regs);
            // dump_exception_state(regs, esr);
            break;
        case ESR_EC_UNKNOWN_REASON:
            unknown_reason_exception(regs);
            break;
        case ESR_EC_BREAKPOINT:
            breakpoint_exception(regs);
            break;
        case ESR_EC_TRAP_SYS_REG:
            trap_sys_exception(regs);
            break;
        default:
            // Linux seems to send SIGILL on ESRs it doesn't know about.
            printf("trap: Unrecognized ESR %016lx on process %s (pid %d), sending SIGILL...\n", esr,
                   get_current_process()->name.data(), get_current_process()->pid_);
            unknown_reason_exception(regs);
            break;
    }

    if (signal_is_pending())
        handle_signal(regs);
}

extern "C" void arm64_exception_serror(struct registers *regs)
{
    panic_exception(regs, mrs(REG_ESR));
}

unsigned long irq_handler(struct registers *regs);

extern "C" void arm64_exception_irq(struct registers *regs)
{
    auto ret = irq_handler(regs);
    DCHECK(ret == (unsigned long) regs);

    if (signal_is_pending())
        handle_signal(regs);
}

extern "C" void arm64_exception_fiq(struct registers *regs)
{
    panic_exception(regs, 0);
}
