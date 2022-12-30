/*
 * Copyright (c) 2019 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
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

static cul::vector<uint32_t> lapic_ids;
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

    if (inited_cpus.is_cpu_set(cpu))
    {
        // CPU was frozen/offlined but is now back online, so instead of doing proper init,
        // we can skip that (since most things are already in memory).
        s->gs_base = percpu_get_area(cpu);

        assert(s->gs_base != 0);
    }
    else
    {
        s->gs_base = percpu_init_for_cpu(cpu);

        other_cpu_write(cpu_nr, cpu, cpu);

        sched_init_cpu(cpu);

        cpu_messages_init(cpu);

        apic_set_lapic_id(cpu, lapic_ids[cpu]);
    }

    s->thread_stack = (unsigned long) get_thread_for_cpu(cpu)->kernel_stack_top;

    if (apic_wake_up_processor(static_cast<uint8_t>(lapic_ids[cpu]), s))
    {
        smp::set_online(cpu);
    }

    inited_cpus.set_cpu(cpu);
}

}; // namespace smp

extern "C" void smp_parse_cpus(void *__madt)
{
    acpi_table_madt *madt = static_cast<acpi_table_madt *>(__madt);
    unsigned int nr_cpus = 0;
    auto first = (acpi_subtable_header *) (madt + 1);
    for (acpi_subtable_header *i = first;
         i < (acpi_subtable_header *) ((char *) madt + madt->header.length);
         i = (acpi_subtable_header *) ((uint64_t) i + (uint64_t) i->length))
    {
        if (i->type == ACPI_MADT_TYPE_LOCAL_APIC)
        {
            acpi_madt_local_apic *la = (acpi_madt_local_apic *) i;

            assert(smp::lapic_ids.push_back(la->id) != false);
            nr_cpus++;
        }
    }

    smp::set_number_of_cpus(nr_cpus);
    cpu_messages_init(0);

    /* We're CPU0 and we're online */
    smp::set_online(0);
}

extern "C" void smp_boot_cpus()
{
    smp::boot_cpus();
}
