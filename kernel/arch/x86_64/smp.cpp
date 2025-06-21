/*
 * Copyright (c) 2019 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/acpi.h>
#include <onyx/cpu.h>
#include <onyx/smp.h>
#include <onyx/vector.h>
#include <onyx/x86/apic.h>

extern struct smp_header smpboot_header;
extern unsigned char _start_smp;

namespace smp
{

static cpumask inited_cpus;

void boot(unsigned int cpu)
{
    printf("smpboot: booting cpu%u\n", cpu);
    /* Get the actual header through some sneaky math */
    unsigned long start_smp = (unsigned long) &_start_smp;
    unsigned long smpboot_header_start = (unsigned long) &smpboot_header;

    unsigned long off = smpboot_header_start - start_smp;

    unsigned long actual_smpboot_header = PHYS_BASE + off;

    struct smp_header *s = (struct smp_header *) actual_smpboot_header;

    s->boot_done = false;
    s->kernel_load_bias = get_kernel_phys_offset();

    const auto gs_base =
        inited_cpus.is_cpu_set(cpu) ? percpu_get_area(cpu) : percpu_init_for_cpu(cpu);

    assert(gs_base != 0);

    if (!inited_cpus.is_cpu_set(cpu))
    {
        other_cpu_write(cpu_nr, cpu, cpu);

        sched_init_cpu(cpu);

        cpu_messages_init(cpu);

        apic_set_lapic_id(cpu, cpu2lapicid(cpu));
    }

    unsigned long *thread_stack = get_thread_for_cpu(cpu)->kernel_stack_top;

    // Stash the gs_base on the top of the stack
    *--thread_stack = gs_base;

    s->thread_stack = (unsigned long) thread_stack;

    if (apic_wake_up_processor(static_cast<uint8_t>(cpu2lapicid(cpu)), s))
        smp::set_online(cpu);

    inited_cpus.set_cpu(cpu);
}

}; // namespace smp

extern "C" void smp_boot_cpus()
{
    smp::boot_cpus();
}
