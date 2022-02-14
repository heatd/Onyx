/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <libfdt.h>
#include <stdio.h>

#include <onyx/device_tree.h>
#include <onyx/paging.h>
#include <onyx/percpu.h>
#include <onyx/random.h>
#include <onyx/riscv/sbi.h>
#include <onyx/serial.h>
#include <onyx/tty.h>
#include <onyx/vm.h>

extern char percpu_base;

void riscv_setup_trap_handling();
void time_init();

extern "C" void kernel_entry(void *fdt)
{
    write_per_cpu(__cpu_base, &percpu_base);
    paging_init();

    platform_serial_init();

    device_tree::init(fdt);

    initialize_entropy();

    vm_update_addresses(arch_high_half);

    paging_protect_kernel();

    vm_late_init();

    console_init();

    printk("Hello World %p\n", fdt);

    riscv_setup_trap_handling();

    sbi_init();

    device_tree::enumerate();

    time_init();
    __builtin_trap();

    while (1)
    {
        __asm__ __volatile("wfi");
    }
}
