/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <libfdt.h>
#include <stdio.h>

#include <onyx/device_tree.h>
#include <onyx/init.h>
#include <onyx/mm/kasan.h>
#include <onyx/paging.h>
#include <onyx/percpu.h>
#include <onyx/random.h>
#include <onyx/serial.h>
#include <onyx/tty.h>
#include <onyx/vdso.h>
#include <onyx/vm.h>

extern char percpu_base;

void time_init();
void riscv_cpu_init();
void plic_init();
extern "C" void arm64_setup_trap_handling();

extern "C" void kernel_entry(void *fdt)
{
    write_per_cpu(__cpu_base, (unsigned long) &percpu_base);
    vm_init();
    arm64_setup_trap_handling();

    platform_serial_init();

    device_tree::init(fdt);

    initialize_entropy();

    vm_update_addresses(arch_high_half);

    paging_protect_kernel();
    platform_serial_write("Done MMU protection\n", sizeof("Done MMU protection\n"));

    vm_late_init();

#ifdef CONFIG_KASAN
    kasan_init();
#endif

    device_tree::enumerate();

    smp::set_number_of_cpus(1);
    smp::set_online(0);
}
