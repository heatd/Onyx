
/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/ktrace.h>
#include <onyx/panic.h>
#include <onyx/platform.h>
#include <onyx/vm.h>

#define UNIMPLEMENTED panic("Not implemented!")

bool platform_has_msi()
{
    return false;
}

void cpu_kill_other_cpus()
{
}

int platform_allocate_msi_interrupts(unsigned int num_vectors, bool addr64,
                                     struct pci_msi_data *data)
{
    UNIMPLEMENTED;
}

bool platform_page_is_used(void *page)
{
    return false;
}

size_t arch_heap_get_size()
{
    return 0x200000000000;
}

void arch_vm_init()
{
}

namespace smp
{

void boot(unsigned int nr)
{
    UNIMPLEMENTED;
}

} // namespace smp

void cpu_send_sync_notif(unsigned int cpu)
{
    UNIMPLEMENTED;
}

extern "C" int do_machine_reboot(unsigned int flags)
{
    UNIMPLEMENTED;
}

extern "C" int do_machine_shutdown(unsigned int flags)
{
    UNIMPLEMENTED;
}

extern "C" int do_machine_halt(unsigned int flags)
{
    UNIMPLEMENTED;
}

extern "C" int do_machine_suspend(unsigned int flags)
{
    return -EIO;
}

void cpu_send_resched(unsigned int cpu)
{
    UNIMPLEMENTED;
}

extern "C" int __enter_sleep_state(uint8_t)
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

void stack_trace()
{
    return;
}

size_t stack_trace_get(unsigned long *stack, unsigned long *pcs, size_t nr_pcs)
{
    return 0;
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

void ktracepoint::activate()
{
    UNIMPLEMENTED;
}

void ktracepoint::deactivate()
{
    UNIMPLEMENTED;
}

} // namespace ktrace
