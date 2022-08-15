/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

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
                                     struct pci_msi_data *data)
{
    UNIMPLEMENTED;
}

size_t arch_heap_get_size(void)
{
    return 0x200000000000;
}

void arch_vm_init()
{
}

int signal_setup_context(struct sigpending *pend, struct k_sigaction *k_sigaction,
                         struct registers *regs)
{
    UNIMPLEMENTED;
}

int platform_install_irq(unsigned int irqn, struct interrupt_handler *h)
{
    UNIMPLEMENTED;
}

void platform_mask_irq(unsigned int irq)
{
    UNIMPLEMENTED;
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

unsigned int get_nr_cpus()
{
    return 1;
}

void cpu_send_resched(unsigned int cpu)
{
    UNIMPLEMENTED;
}

bool cpu_send_message(unsigned int cpu, unsigned long message, void *arg, bool should_wait)
{
    UNIMPLEMENTED;
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

void ktracepoint::activate()
{
    UNIMPLEMENTED;
}

void ktracepoint::deactivate()
{
    UNIMPLEMENTED;
}

} // namespace ktrace
