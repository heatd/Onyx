/*
 * Copyright (c) 2022 - 2923 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <libfdt.h>
#include <stdio.h>

#include <onyx/cmdline.h>
#include <onyx/device_tree.h>
#include <onyx/init.h>
#include <onyx/mm/kasan.h>
#include <onyx/paging.h>
#include <onyx/percpu.h>
#include <onyx/random.h>
#include <onyx/riscv/sbi.h>
#include <onyx/serial.h>
#include <onyx/tty.h>
#include <onyx/vdso.h>
#include <onyx/vm.h>

extern char percpu_base;

void riscv_setup_trap_handling();
void time_init();
void riscv_cpu_init(unsigned long hartid);
void plic_init();

static void riscv_enable_interrupts()
{
    riscv_or_csr(RISCV_SIE, RISCV_SIE_STIE | RISCV_SIE_SEIE | RISCV_SIE_SSIE);
    irq_enable();
}

extern "C" void kernel_entry(unsigned long hartid, void *fdt)
{
    // XXX HACK
    set_kernel_cmdline("--root=/dev/sda1");
    write_per_cpu(__cpu_base, &percpu_base);
    paging_init();

    platform_serial_init();

    riscv_setup_trap_handling();

    device_tree::init(fdt);

    initialize_entropy();

    vm_update_addresses(arch_high_half);

    paging_protect_kernel();

    vm_late_init();

#ifdef CONFIG_KASAN
    kasan_init();
#endif

    console_init();

    printf("riscv: Booted on hart%lu\n", hartid);

    sbi_init();

    device_tree::enumerate();

    time_init();

    riscv_cpu_init(hartid);

    plic_init();

    riscv_enable_interrupts();
}

extern "C" void smpboot_main(unsigned long hartid)
{
    riscv_setup_trap_handling();

    riscv_cpu_init(hartid);
    printf("riscv: hart%lu (cpu%u) online\n", hartid, get_cpu_nr());

    time_init();

    sched_enable_pulse();

    riscv_enable_interrupts();

    sched_transition_to_idle();
}

void init_arch_vdso()
{
    vdso_init();
}

INIT_LEVEL_EARLY_CORE_KERNEL_ENTRY(init_arch_vdso);
