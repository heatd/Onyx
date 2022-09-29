/*
 * Copyright (c) 2022 Pedro Falcato
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
void riscv_cpu_init();
void plic_init();

extern "C" void kernel_entry(void *fdt)
{
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

    sbi_init();

    device_tree::enumerate();

    time_init();

    riscv_cpu_init();

    plic_init();
}

void init_arch_vdso()
{
    vdso_init();
}

INIT_LEVEL_EARLY_CORE_KERNEL_ENTRY(init_arch_vdso);
