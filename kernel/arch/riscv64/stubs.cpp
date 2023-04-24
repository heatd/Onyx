/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/arch.h>
#include <onyx/irq.h>
#include <onyx/ktrace.h>
#include <onyx/panic.h>
#include <onyx/platform.h>
#include <onyx/vm.h>

#define UNIMPLEMENTED panic("Not implemented!")

void cpu_kill_other_cpus()
{
}

int platform_allocate_msi_interrupts(unsigned int num_vectors, bool addr64,
                                     struct pci_msi_data *data, unsigned int flags,
                                     unsigned int target_cpu)
{
    UNIMPLEMENTED;
}

void arch_vm_init()
{
}

extern "C" void __enter_sleep_state()
{
    UNIMPLEMENTED;
}

uintptr_t get_rdsp_from_grub(void)
{
    return 0;
}

void reclaim_initrd(void)
{
}

uint64_t get_posix_time_early()
{
    return 0;
}

void setup_kernel_symbols(struct module *m)
{
}

namespace entropy
{

namespace platform
{

unsigned long get_seed()
{
    return 0;
}

unsigned long get_hwrandom()
{
    return 0;
}

void init_random()
{
}

} // namespace platform

} // namespace entropy

void platform_init_acpi()
{
    UNIMPLEMENTED;
}

namespace ktrace
{

void old_broken_ktracepoint::activate()
{
    UNIMPLEMENTED;
}

void old_broken_ktracepoint::deactivate()
{
    UNIMPLEMENTED;
}

} // namespace ktrace
