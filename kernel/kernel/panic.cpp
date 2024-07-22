/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
/**************************************************************************
 *
 *
 * File: panic.c
 *
 * Description: Contains the implementation of the panic function
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/irq.h>
#include <onyx/modules.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/process.h>
#include <onyx/registers.h>
#include <onyx/task_switching.h>
#include <onyx/vm.h>

#include <platform/irq.h>

const char *skull = "            _,,,,,,,_\n\
          ,88888888888,\n\
        ,888\'       \\`888,\n\
        888\' 0     0 \\`888\n\
       888      0      888\n\
       888             888\n\
       888    ,000,    888\n\
        888, 0     0 ,888\n\
        \'888,       ,888\'\n\
          \'8JGS8888888\'\n\
            \\`\\`\\`\\`\\`\\`\\`\\`\n";
int panicing = 0;

void stack_trace(void);

void page_print_shared(void);

void vterm_panic(void);

void bust_printk_lock(void);

PER_CPU_VAR(bool in_panic) = false;
PER_CPU_VAR(bool start_end) = false;

#define PANIC_STACK_BUF_SZ 1024

bool is_in_panic()
{
    return get_per_cpu(in_panic);
}

void panic_start()
{
    irq_disable();

    if (get_per_cpu(in_panic))
        halt();

    write_per_cpu(in_panic, true);
    write_per_cpu(start_end, true);

    /* Turn off vterm multthreading */
    vterm_panic();

    bust_printk_lock();
}

[[gnu::weak]] void print_int_stacks()
{
    /* Overriden by architectures */
}

__attribute__((noreturn, noinline)) void panic(const char *msg, ...)
{
    /* First, disable interrupts */
    irq_disable();

    if (get_per_cpu(in_panic) && !get_per_cpu(start_end))
        halt();

    write_per_cpu(in_panic, true);

    char buffer[PANIC_STACK_BUF_SZ];
    panicing = 1;
    buffer[PANIC_STACK_BUF_SZ - 1] = '\0';

    va_list parameters;
    va_start(parameters, msg);

    vsnprintf(buffer, PANIC_STACK_BUF_SZ, msg, parameters);

    va_end(parameters);

    if (!get_per_cpu(start_end))
    {
        /* Turn off vterm multthreading */
        vterm_panic();

        bust_printk_lock();
    }

    /* And dump the context to it */
#if 0
#ifdef __x86_64__
#else
#error "Implement thread context printing in your arch"
#endif
#endif
    pr_emerg("panic: %s\n", buffer);

    module_dump();
    pr_emerg("Stack dump: \n");

    stack_trace();
    print_int_stacks();
    pr_emerg("Killing cpus... ");
    cpu_kill_other_cpus();
    pr_emerg("Done.\n");
    halt();
    __builtin_unreachable();
}

void __assert_fail(const char *assertion, const char *file, int line, const char *function)
{
    panic("Assertion %s failed in %s:%u, in function %s\n", assertion, file, line, function);
}

void abort(void)
{
    panic("Abort!");
}
