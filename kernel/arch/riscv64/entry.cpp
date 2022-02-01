/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <libfdt.h>

#include <onyx/serial.h>
#include <onyx/tty.h>
#include <onyx/paging.h>
#include <onyx/device_tree.h>
#include <onyx/random.h>
#include <onyx/vm.h>
#include <onyx/percpu.h>

static char buffer[1000];

#define budget_printk(...) snprintf(buffer, sizeof(buffer), __VA_ARGS__); platform_serial_write(buffer, strlen(buffer))

extern char percpu_base;

extern "C"
void kernel_entry(void *fdt)
{
    write_per_cpu(__cpu_base, &percpu_base);
    platform_serial_init();

    platform_serial_write("Hello", strlen("Hello"));

    paging_init();

    platform_serial_write("Hello2", strlen("Hello2"));
    budget_printk("FDT: %p\n", fdt);

    device_tree::init(fdt);

    initialize_entropy();

    vm_update_addresses(arch_high_half);

    vm_late_init();

	paging_protect_kernel();

    console_init();

    printk("Hello World %p\n", fdt);

    while(1)
    {
        __asm__ __volatile("wfi");
    }
}
