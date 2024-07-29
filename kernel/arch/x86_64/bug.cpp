/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/bug.h>
#include <onyx/cpu.h>
#include <onyx/process.h>
#include <onyx/registers.h>

#include <onyx/linker_section.hpp>

DEFINE_LINKER_SECTION_SYMS(__start___bug_tab, __end___bug_tab);

static linker_section bug_sec{&__start___bug_tab, &__end___bug_tab};

static struct bug *find_bug(unsigned long ip)
{
    size_t nr = bug_sec.size() / sizeof(struct bug);
    struct bug *bug = bug_sec.as<struct bug>();
    for (size_t i = 0; i < nr; i++, bug++)
    {
        if (bug->addr == ip)
            return bug;
    }

    return nullptr;
}

static void print_splat(struct bug *bug, struct registers *ctx, const char *lvl)
{
    pr_warn("WARNING: CPU: %u PID: %d at %s:%u %pS\n", get_cpu_nr(),
            get_current_process() ? get_current_process()->pid_ : 0, bug->file, bug->line,
            (void *) bug->addr);
    printk("%srax: %016lx  rbx: %016lx  rcx: %016lx  rdx: %016lx\n", lvl, ctx->rax, ctx->rbx,
           ctx->rcx, ctx->rdx);
    printk("%srdi: %016lx  rsi: %016lx  rbp: %016lx  r8:  %016lx\n", lvl, ctx->rdi, ctx->rsi,
           ctx->rbp, ctx->r8);
    printk("%sr9:  %016lx  r10: %016lx  r11: %016lx  r12: %016lx\n", lvl, ctx->r9, ctx->r10,
           ctx->r11, ctx->r12);
    printk("%sr13: %016lx  r14: %016lx  r15: %016lx  rsp: %016lx\n", lvl, ctx->r13, ctx->r14,
           ctx->r15, ctx->rsp);
    printk("%srflags: %08lx  ds: %04lx  cs: %04lx  cr0: %08lx\n", lvl, ctx->rflags, ctx->ds,
           ctx->cs, cpu_get_cr0());
    printk("%scr2: %016lx  cr3: %016lx  cr4: %08lx\n", lvl, cpu_get_cr2(), cpu_get_cr3(),
           cpu_get_cr4());
    stack_trace_ex((uint64_t *) ctx->rbp);
}

bool handle_bug(struct registers *ctx)
{
    struct bug *bug = find_bug(ctx->rip);
    if (!bug)
        return false;
    print_splat(bug, ctx, KERN_WARN);
    ctx->rip += 2;
    return true;
}
