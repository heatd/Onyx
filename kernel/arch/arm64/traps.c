/*
 * Copyright (c) 2022 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <stdio.h>

#include <onyx/exceptions.h>
#include <onyx/intrinsics.h>
#include <onyx/process.h>
#include <onyx/registers.h>
#include <onyx/serial.h>
#include <onyx/vm.h>

extern char arm64_exception_vector_table[];

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
    printk(KERN_WARN regs_format(regs, esr));
}

void panic_exception(struct registers *regs, unsigned long esr)
{
    dump_exception_state(regs, esr);
    panic(regs_format(regs, esr));
}

#define DATA_ABORT_WNR (1U << 6)
#define CONFIG_VERBOSE_SEGV
#ifdef CONFIG_VERBOSE_SEGV
#undef REQUIRES_SHARED
#define REQUIRES_SHARED(...)
struct vm_area_struct *vm_search(struct mm_address_space *mm, void *addr, size_t length)
    REQUIRES_SHARED(mm->vm_lock);

#define dumpprint printk
struct mutex dumplock;

static void attempt_map_pointer(unsigned long word)
{
#define BUFSZ 1024
    char buf[BUFSZ];
    size_t pos = 0;
    struct mm_address_space *mm = get_current_address_space();

    rw_lock_read(&mm->vm_lock);
    // Lets try to "symbolize" it
    struct vm_area_struct *vm = vm_search(mm, (void *) word, 1);
    if (vm)
    {
        pos += snprintf(buf + pos, BUFSZ - pos, " ^^ refers to ");

        if (vm->vm_file)
        {
            size_t off = vm->vm_offset;
            pos += snprintf(buf + pos, BUFSZ - pos, "%s+%lx", vm->vm_file->f_dentry->d_name,
                            off + (word - vm->vm_start));
        }
        else
            pos += snprintf(buf + pos, BUFSZ - pos, " [anon region + %lx]", (word - vm->vm_start));

        if (vm->vm_flags & VM_EXEC)
            pos += snprintf(buf + +pos, BUFSZ - pos, " # executable (.text?)");
        dumpprint("%s\n", buf);
    }

    rw_unlock_read(&mm->vm_lock);
#undef BUFSZ
}

static void dumpstack(unsigned long pc, unsigned long lr, const void *stack)
{
    unsigned long words[32] = {0, 0, 0, 0};

    mutex_lock(&dumplock);
    dumpprint("PC: %016lx", pc);
    attempt_map_pointer(pc);
    dumpprint("LR: %016lx", lr);
    attempt_map_pointer(lr);

    if (copy_from_user(words, (const void *) stack, sizeof(words)) < 0)
    {
        pr_info("trap: dumpstack faulted, skipping stack dump\n");
        mutex_unlock(&dumplock);
        return;
    }

    for (int i = 0; i < 32; i++)
    {
        unsigned long word = words[i];
        // Lets try to "symbolize" it
        dumpprint("stack#%d: %016lx", i, words[i]);
        attempt_map_pointer(word);
    }
    mutex_unlock(&dumplock);
}

#else
#define dumpstack(a, b)
#endif

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

        dumpstack(regs->pc, regs->x[30], (const void *) regs->sp);
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

    raise_sig_curthr(SIGILL, SIGNAL_FORCE, &info);
}

#define TRAP_SYS_OP0(x) (((x) >> 20) & 3)
#define TRAP_SYS_OP2(x) ((x) >> 17) & 7)
#define TRAP_SYS_OP1(x) ((x) >> 14) & 7)
#define TRAP_SYS_CRn(x) ((x) >> 10) & 0xf)
#define TRAP_SYS_Rt(x) ((x) >> 5) & 0x1f)
#define TRAP_SYS_CRm(x) ((x) >> 1) & 0x1f)
#define TRAP_SYS_DIR(x) (x & 1)

static void trap_sys_exception(struct registers *regs, unsigned long esr)
{
    /* TODO: Maybe decompose the ISS as specified in "ISS encoding for an exception from MSR, MRS,
     * or System instruction execution in AArch64 state". Macros above. */
    siginfo_t info = {};
    info.si_code = ILL_PRVREG;
    info.si_addr = (void *) regs->pc;

    printf("trap: MSR/MRS/system exception ESR %08lx on process %s (pid %d)\n", esr, current->comm,
           current->pid_);

    raise_sig_curthr(SIGILL, SIGNAL_FORCE, &info);
}

static void breakpoint_exception(registers_t *ctx)
{
    siginfo_t info = {};
    info.si_code = TRAP_BRKPT;

    raise_sig_curthr(SIGTRAP, SIGNAL_FORCE, &info);
}

void arm64_exception_sync(struct registers *regs)
{
    unsigned long esr = mrs(REG_ESR);
    const unsigned long eclass = ESR_EC_CLASS(esr);
    if (get_current_thread())
        get_current_thread()->regs = regs;

    if (in_kernel_space_regs(regs))
    {
        if (eclass != (ESR_EC_DATA_ABORT | ESR_INSN_DATA_ABORT_NO_EL_CHANGE))
        {
            // If we cannot handle this fault with exception handlers (atm, data abort only)
            // just panic.
            panic_exception(regs, esr);
        }
    }
    else
    {
        CHECK(regs == (struct registers *) task_curr_syscall_frame());
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
            if (current->pid_ == 1)
            {
                // pr_warn("curr %s[%d]\n", current->comm, current->pid_);
                // dump_exception_state(regs, esr);
            }
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
            trap_sys_exception(regs, esr);
            break;
        default:
            // Linux seems to send SIGILL on ESRs it doesn't know about.
            pr_err("trap: Unrecognized ESR %016lx on process %s (pid %d), sending SIGILL...\n", esr,
                   current->comm, current->pid_);
            unknown_reason_exception(regs);
            break;
    }
}

void arm64_exception_serror(struct registers *regs)
{
    panic_exception(regs, mrs(REG_ESR));
}

unsigned long irq_handler(struct registers *regs);

void arm64_exception_irq(struct registers *regs)
{
    if (get_current_thread())
        get_current_thread()->regs = regs;

    unsigned long ret = irq_handler(regs);
    DCHECK(ret == (unsigned long) regs);
}

void arm64_exception_fiq(struct registers *regs)
{
    panic_exception(regs, 0);
}
