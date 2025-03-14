/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <xmmintrin.h>

#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/dentry.h>
#include <onyx/disassembler.h>
#include <onyx/exceptions.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/perf_probe.h>
#include <onyx/process.h>
#include <onyx/signal.h>
#include <onyx/task_switching.h>
#include <onyx/vm.h>
#include <onyx/x86/isr.h>
#include <onyx/x86/ktrace.h>
#include <onyx/x86/mce.h>
#include <onyx/x86/msr.h>

/* TODO: Move scope_guard somewhere else */
#include <onyx/trace/trace_base.h>

#include <uapi/signal.h>

const char *exception_msg[] = {"Division by zero exception",
                               "Debug Trap",
                               "Non-maskable interrupt",
                               "Hit a breakpoint",
                               "Overflow trap",
                               "Fault: Bound range exceeded",
                               "Invalid Instruction",
                               "FPU not detected",
                               "Critical error: DOUBLE FAULT",
                               "Invalid TSS",
                               "Segment not present",
                               "Stack segment fault",
                               "General Protection Fault",
                               "Page fault at ",
                               "",
                               "x87 floating point exception",
                               "Alignment check exception",
                               "Machine check exception",
                               "SIMD floating point exception",
                               "Virtualization exception",
                               "",
                               "",
                               "",
                               "",
                               "",
                               "",
                               "",
                               "",
                               "",
                               "Security exception"};

void dump_interrupt_context(struct registers *ctx)
{
    printk("Exception at %016lx\n", ctx->rip);
    printk("Registers: rax: %016lx\nrbx: %016lx\nrcx: %016lx\nrdx: %016lx\n"
           "rdi: %016lx\nrsi: %016lx\nrbp: %016lx\nr8:  %016lx\nr9:  %016lx\n"
           "r10: %016lx\nr11: %016lx\nr12: %016lx\nr13: %016lx\nr14: %016lx\n"
           "r15: %016lx\nrsp: %016lx\nrflags: %016lx\nds: %016lx\ncs: %016lx\n",
           ctx->rax, ctx->rbx, ctx->rcx, ctx->rdx, ctx->rdi, ctx->rsi, ctx->rbp, ctx->r8, ctx->r9,
           ctx->r10, ctx->r11, ctx->r12, ctx->r13, ctx->r14, ctx->r15, ctx->rsp, ctx->rflags,
           ctx->ds, ctx->cs);

    if (ctx->cs == 0x08)
        stack_trace_ex((uint64_t *) ctx->rbp);
}

static bool is_kernel_exception(struct registers *ctx)
{
    /* We can't use %rip here since, for example, in a page fault, %rip is
     * set to the target address before the page fault actually triggers.
     * User-space cannot set cs.
     */
    return ctx->cs == 0x08;
}

void div0_exception(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("Divide by zero exception");
    }

    siginfo_t info = {};
    info.si_code = SI_KERNEL;

    raise_sig_curthr(SIGFPE, SIGNAL_FORCE, &info);
}

#define MSR_IA32_DEBUGCTLMSR      0x000001d9
#define MSR_IA32_LASTBRANCHFROMIP 0x000001db
#define MSR_IA32_LASTBRANCHTOIP   0x000001dc
#define MSR_IA32_LASTINTFROMIP    0x000001dd
#define MSR_IA32_LASTINTTOIP      0x000001de

#define MSR_IA32_PASID       0x00000d93
#define MSR_IA32_PASID_VALID BIT_ULL(31)

/* DEBUGCTLMSR bits (others vary by model): */
#define DEBUGCTLMSR_LBR_BIT               0 /* last branch recording */
#define DEBUGCTLMSR_LBR                   (1UL << DEBUGCTLMSR_LBR_BIT)
#define DEBUGCTLMSR_BTF_SHIFT             1
#define DEBUGCTLMSR_BTF                   (1UL << 1) /* single-step on branches */
#define DEBUGCTLMSR_BUS_LOCK_DETECT       (1UL << 2)
#define DEBUGCTLMSR_TR                    (1UL << 6)
#define DEBUGCTLMSR_BTS                   (1UL << 7)
#define DEBUGCTLMSR_BTINT                 (1UL << 8)
#define DEBUGCTLMSR_BTS_OFF_OS            (1UL << 9)
#define DEBUGCTLMSR_BTS_OFF_USR           (1UL << 10)
#define DEBUGCTLMSR_FREEZE_LBRS_ON_PMI    (1UL << 11)
#define DEBUGCTLMSR_FREEZE_PERFMON_ON_PMI (1UL << 12)
#define DEBUGCTLMSR_FREEZE_IN_SMM_BIT     14
#define DEBUGCTLMSR_FREEZE_IN_SMM         (1UL << DEBUGCTLMSR_FREEZE_IN_SMM_BIT)

void debug_trap(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        // printk("Trap at %lx rbp %lx!\n", ctx->rip, ctx->rbp);
        dump_interrupt_context(ctx);
        panic("Debug trap");
    }

    pr_info("%d trap at %lx\n", get_current_process()->pid_, ctx->rip);
    wrmsr(MSR_IA32_DEBUGCTLMSR, DEBUGCTLMSR_LBR | DEBUGCTLMSR_BTF);
    return;
    siginfo_t info = {};
    info.si_code = SI_KERNEL;

    raise_sig_curthr(SIGTRAP, SIGNAL_FORCE, &info);
}

void nmi_exception(struct registers *ctx)
{
    dump_interrupt_context(ctx);
    /* TODO: Handle this in a better, less destructive and useful fashion */
    panic("Unexpected NMI exception\n");
}

void overflow_trap(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("Overflow trap");
    }

    siginfo_t info = {};
    info.si_code = SEGV_BNDERR;

    raise_sig_curthr(SIGSEGV, SIGNAL_FORCE, &info);
}

void boundrange_exception(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("Bound range trap");
    }

    siginfo_t info = {};
    info.si_code = SI_KERNEL;

    raise_sig_curthr(SIGILL, SIGNAL_FORCE, &info);
}

bool handle_bug(struct registers *ctx);
void invalid_opcode_exception(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        if (handle_bug(ctx))
            return;
        dump_interrupt_context(ctx);
        panic("Invalid instruction exception");
    }

    siginfo_t info = {};
    info.si_code = SI_KERNEL;

    raise_sig_curthr(SIGILL, SIGNAL_FORCE, &info);
}

void device_not_avail_excp(struct registers *ctx)
{
    /* We don't support FPU lazy switching right now, so we just send SIGFPE
     * to the process
     */
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("FPU exception");
    }

    siginfo_t info = {};
    info.si_code = SI_KERNEL;

    raise_sig_curthr(SIGFPE, SIGNAL_FORCE, &info);
}
void __double_fault(struct registers *ctx)
{
    dump_interrupt_context(ctx);
    panic("Double fault");
}

void exception_panic(struct registers *ctx)
{
    dump_interrupt_context(ctx);
    panic("Misc/Unknown exception triggered.");
}

void stack_segment_fault(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("Stack segment fault");
    }

    siginfo_t info = {};
    info.si_code = SEGV_BNDERR;

    raise_sig_curthr(SIGSEGV, SIGNAL_FORCE, &info);
}

#ifdef CONFIG_VERBOSE_SEGV
#undef REQUIRES_SHARED
#define REQUIRES_SHARED(...)
extern "C" vm_area_struct *vm_search(struct mm_address_space *mm, void *addr, size_t length)
    REQUIRES_SHARED(mm->vm_lock);

#define dumpprint printk
mutex dumplock;

static void attempt_map_pointer(unsigned long word)
{
#define BUFSZ 1024
    char buf[BUFSZ];
    size_t pos = 0;
    struct mm_address_space *mm = get_current_address_space();

    scoped_rwlock<rw_lock::read> g{mm->vm_lock};
    // Lets try to "symbolize" it
    struct vm_area_struct *vm = vm_search(mm, (void *) word, 1);
    if (vm)
    {
        pos += snprintf(buf + pos, BUFSZ - pos, " ^^ refers to ");

        if (vm->vm_file)
        {
            auto off = vm->vm_offset;
            pos += snprintf(buf + pos, BUFSZ - pos, "%s+%lx", vm->vm_file->f_dentry->d_name,
                            off + (word - vm->vm_start));
        }
        else
            pos += snprintf(buf + pos, BUFSZ - pos, " [anon region + %lx]", (word - vm->vm_start));

        if (vm->vm_flags & VM_EXEC)
            pos += snprintf(buf + +pos, BUFSZ - pos, " # executable (.text?)");
        dumpprint("%s\n", buf);
    }
#undef BUFSZ
}

static void dumpstack(unsigned long rip, const void *stack)
{
    scoped_mutex g{dumplock};
    unsigned long words[32] = {0, 0, 0, 0};

    dumpprint("RIP: %016lx", rip);
    attempt_map_pointer(rip);

    if (copy_from_user(words, (const void *) stack, sizeof(words)) < 0)
    {
        pr_info("trap: dumpstack faulted, skipping stack dump\n");
        return;
    }

    for (int i = 0; i < 32; i++)
    {
        unsigned long word = words[i];
        // Lets try to "symbolize" it
        dumpprint("stack#%d: %016lx", i, words[i]);
        attempt_map_pointer(word);
    }
}

#else
#define dumpstack(a, b)
#endif

void general_protection_fault(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        unsigned long fixup;
        if ((fixup = exceptions_get_fixup(ctx->rip)) != NO_FIXUP_EXISTS)
        {
            ctx->rip = fixup;
            return;
        }

        dump_interrupt_context(ctx);
        printk("GPF error code: %04x\n", (uint16_t) ctx->int_err_code);
        panic("General protection fault");
    }

    struct thread *current = get_current_thread();
    (void) current;
    dump_interrupt_context(ctx);
    unsigned long image_base = (unsigned long) current->owner->image_base;

    if (image_base)
    {
        printk("Image base: %lx\n", image_base);
        printk("Adjusted ip: %lx\n", ctx->rip - image_base);
        // printk("Adjusted to interp(%p): %lx\n", current->owner->interp_base, ctx->rip - (unsigned
        // long) current->owner->interp_base); printk("Process: %s\n",
        // current->owner->cmd_line.c_str());
    }

    unsigned char instr[16];
    memset(instr, 0, sizeof(instr));
    if (copy_from_user(instr, (void *) ctx->rip, sizeof(instr)) >= 0)
    {
        printk("Instruction (16 raw bytes): ");
        for (int i = 0; i < 16; i++)
            printk("%02x ", instr[i]);
        printk("\n");
    }

    printk("GPF error code: %04x\n", (uint16_t) ctx->int_err_code);

    siginfo_t info = {};
    info.si_code = SEGV_MAPERR;

    dumpstack(ctx->rip, (const void *) ctx->rsp);

    raise_sig_curthr(SIGSEGV, SIGNAL_FORCE, &info);
}

void stack_trace_user(uintptr_t *stack);

bool vm_is_smap_fault(struct registers *regs, const fault_info &info)
{
    if (info.fault_address >= arch_high_half)
        return false;

    if (info.user)
        return false;

    return !(regs->rflags & EFLAGS_ALIGNMENT_CHECK) && x86_has_cap(X86_FEATURE_SMAP);
}

void page_fault_handler(struct registers *ctx)
{
    uintptr_t fault_address = cpu_get_cr2();

    // IRQ restores need to be deferred after we collect all the state associated with the fault
    // namely, CR2.
    irq_restore(ctx->rflags);
    uint16_t error_code = ctx->int_err_code;

    struct fault_info info;
    info.signal = VM_SIGSEGV;
    info.fault_address = fault_address;
    info.write = error_code & 0x2;
    info.read = info.write ? 0 : 1;
    info.exec = error_code & 0x10;
    info.user = error_code & 0x4;
    info.ip = ctx->rip;
    info.error_info = 0;

    if (vm_is_smap_fault(ctx, info) || vm_handle_page_fault(&info) < 0)
    {
        if (!info.user)
        {
            unsigned long fixup;
            if ((fixup = exceptions_get_fixup(info.ip)) != NO_FIXUP_EXISTS)
            {
                ctx->rip = fixup;
                return;
            }
        }

        vm_do_fatal_page_fault(&info);
        dumpstack(ctx->rip, (const void *) ctx->rsp);
    }

    if (WARN_ON(sched_is_preemption_disabled()))
    {
        pr_err("Trying to return from a page fault with preemption disabled (%lx)! Fixing up...\n",
               sched_get_preempt_counter());
        write_per_cpu(preemption_counter, 0);
    }
}

void x87_fpu_exception(struct registers *ctx)
{
    /* We don't support FPU lazy switching right now, so we just send SIGFPE
     * to the process
     */
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("FPU exception");
    }

    siginfo_t info = {};
    info.si_code = SI_KERNEL;

    raise_sig_curthr(SIGFPE, SIGNAL_FORCE, &info);
}

void alignment_check_excp(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("Alignment check exception");
    }

    siginfo_t info = {};
    info.si_code = SEGV_ACCERR;

    raise_sig_curthr(SIGSEGV, SIGNAL_FORCE, &info);
}

void simd_fpu_exception(struct registers *ctx)
{
    /* We don't support FPU lazy switching right now, so we just send SIGFPE
     * to the process
     */
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("FPU exception");
    }

    siginfo_t info = {};
    info.si_code = SI_KERNEL;

    raise_sig_curthr(SIGFPE, SIGNAL_FORCE, &info);
}

void virtualization_exception(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("Virtualization exception");
    }

    siginfo_t info = {};
    info.si_code = SI_KERNEL;

    raise_sig_curthr(SIGSEGV, SIGNAL_FORCE, &info);
}

void security_exception(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("Security exception");
    }

    siginfo_t info = {};
    info.si_code = SI_KERNEL;

    raise_sig_curthr(SIGSEGV, SIGNAL_FORCE, &info);
}

#ifdef CONFIG_KTRACE

bool ktrace_enabled_int3 = false;

void ktrace_enable_int3(void)
{
    ktrace_enabled_int3 = true;
}

void ktrace_disable_int3(void)
{
    ktrace_enabled_int3 = true;
}
#endif

void breakpoint_exception(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
#ifdef CONFIG_KTRACE
        if (ktrace_enabled_int3)
        {
            ktrace_int3_handler(ctx);
            return;
        }
#endif
        dump_interrupt_context(ctx);
        panic("Breakpoint exception");
    }

    siginfo_t info = {};
    info.si_code = SI_KERNEL;
    dumpstack(ctx->rip, (const void *) ctx->rsp);
    raise_sig_curthr(SIGTRAP, SIGNAL_FORCE, &info);
}

void invalid_tss_exception(struct registers *ctx)
{
    dump_interrupt_context(ctx);
    panic("Invalid TSS exception");
}

void segment_not_present_excp(struct registers *ctx)
{
    if (is_kernel_exception(ctx))
    {
        dump_interrupt_context(ctx);
        panic("Segment not present exception");
    }

    siginfo_t info = {};
    info.si_code = SI_KERNEL;

    raise_sig_curthr(SIGSEGV, SIGNAL_FORCE, &info);
}

void machine_check(struct registers *ctx)
{
    do_machine_check(ctx);
}

void (*const int_handlers[])(struct registers *ctx) = {div0_exception,
                                                       debug_trap,
                                                       nmi_exception,
                                                       breakpoint_exception,
                                                       overflow_trap,
                                                       boundrange_exception,
                                                       invalid_opcode_exception,
                                                       device_not_avail_excp,
                                                       __double_fault,
                                                       exception_panic,
                                                       invalid_tss_exception,
                                                       segment_not_present_excp,
                                                       stack_segment_fault,
                                                       general_protection_fault,
                                                       page_fault_handler,
                                                       exception_panic,
                                                       x87_fpu_exception,
                                                       alignment_check_excp,
                                                       machine_check,
                                                       simd_fpu_exception,
                                                       virtualization_exception,
                                                       exception_panic,
                                                       exception_panic,
                                                       exception_panic,
                                                       exception_panic,
                                                       exception_panic,
                                                       exception_panic,
                                                       exception_panic,
                                                       exception_panic,
                                                       exception_panic,
                                                       security_exception,
                                                       exception_panic};

PER_CPU_VAR(struct spinlock isr_lock);
uint32_t in_isr = 0;

static void exit_isr_handler(void)
{
    in_isr--;
    // spin_unlock(&GET_PER_CPU(isr_lock, struct spinlock));
}

static void enter_isr_handler(void)
{
    if (in_isr > 10)
    {
        halt();
    }
    in_isr++;
    // spin_lock(&GET_PER_CPU(isr_lock, struct spinlock));
}

void dump_stack(uintptr_t *__rsp)
{
    unsigned char *rsp = (unsigned char *) __rsp;
    printk("Stack dump: ");
    /* Lets dump a comfortable number of bytes */
    for (int i = 0; i < 20; i++, rsp--)
        printk("%02x ", *rsp);
    printk("\n");
}

static bool defer_irq_restore(int int_no)
{
    // Page faults need to read cr2 before getting interrupted again.
    return int_no == 14;
}

struct trap_stack
{
    struct registers *ctx;
    struct trap_stack *next;
};

PER_CPU_VAR(static struct trap_stack *cur_stack);

unsigned long isr_handler(struct registers *ctx)
{
    int int_no = ctx->int_no;

    if (!defer_irq_restore(int_no))
        irq_restore(ctx->rflags);

    int_handlers[int_no](ctx);

    return INTERRUPT_STACK_ALIGN(ctx);
}

void print_int_stacks()
{
    /* Follow the chain of trap stacks */
    struct trap_stack *tps = get_per_cpu(cur_stack);
    while (tps)
    {
        const char *type = "IRQ";
        bool is_trap = false;
        const struct registers *ctx = tps->ctx;
        struct trap_stack *next = tps->next;
        if (next)
        {
            if (tps->ctx->int_no < EXCEPTION_VECTORS_END)
                type = "TRAP";
            is_trap = true;
        }
        else
        {
            is_trap = false;
            type = "THREAD";
        }

        if (ctx->rbp < VM_HIGHER_HALF)
        {
            /* User or corrupted stack, skip */
            pr_emerg(" (%s stack skipped, bad stack)\n", type);
            tps = next;
            break;
        }

        if (is_trap)
            pr_emerg("<%s %u>\n", type, (unsigned int) ctx->int_no);
        else
            pr_emerg("<%s>\n", type);
        pr_emerg(" %pS\n", (void *) ctx->rip);
        stack_trace_ex((u64 *) ctx->rbp);
        if (is_trap)
            pr_emerg("</%s %u>\n", type, (unsigned int) ctx->int_no);
        else
            pr_emerg("</%s>\n", type);
        tps = next;
    }
}
void platform_send_eoi(uint64_t irq);

static auto isr_enter_stack(struct registers *regs, struct trap_stack *trapstack)
{
    trapstack->ctx = regs;
    trapstack->next = get_per_cpu(cur_stack);
    write_per_cpu(cur_stack, trapstack);
    return scope_guard{[trapstack]() { write_per_cpu(cur_stack, trapstack->next); }};
}

void isr_undo_trap_stack()
{
    write_per_cpu(cur_stack, get_per_cpu(cur_stack)->next);
}

extern "C" unsigned long x86_dispatch_interrupt(struct registers *regs)
{
    unsigned long vec_no = regs->int_no;
    unsigned long result;
    struct trap_stack tpstack;

    context_tracking_enter_kernel();
    if (get_current_thread())
        get_current_thread()->regs = regs;
    auto undo_ = isr_enter_stack(regs, &tpstack);

    if (vec_no < EXCEPTION_VECTORS_END)
    {
        auto ret = isr_handler(regs);
        context_tracking_exit_kernel();
        return ret;
    }

    platform_send_eoi(vec_no - EXCEPTION_VECTORS_END);

    if (vec_no == X86_MESSAGE_VECTOR)
        result = INTERRUPT_STACK_ALIGN(cpu_handle_messages(regs));
    else if (vec_no == X86_RESCHED_VECTOR)
        result = INTERRUPT_STACK_ALIGN(cpu_resched(regs));
    else if (vec_no == X86_SYNC_CALL_VECTOR)
    {
        smp::cpu_handle_sync_calls();
        result = INTERRUPT_STACK_ALIGN(regs);
    }
    else if (vec_no == X86_PERFPROBE)
    {
        result = INTERRUPT_STACK_ALIGN(regs);
        if (perf_probe_is_enabled() && in_kernel_space_regs(regs))
            perf_probe_do(regs);
    }
    else
        result = INTERRUPT_STACK_ALIGN(irq_handler(regs));

    context_tracking_exit_kernel();

    return result;
}
