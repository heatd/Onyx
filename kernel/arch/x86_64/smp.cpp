/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <onyx/acpi.h>
#include <onyx/vector.h>
#include <onyx/x86/apic.h>
#include <onyx/smp.h>
#include <onyx/cpu.h>

extern struct smp_header smpboot_header;
extern unsigned char _start_smp;

namespace smp
{

static cul::vector<uint32_t> lapic_ids;

extern "C"
{
	extern unsigned int cpu_nr;
};

void boot(unsigned int cpu)
{
	printf("smpboot: booting cpu%u\n", cpu);
	/* Get the actual header through some sneaky math */
	unsigned long start_smp = (unsigned long) &_start_smp;
	unsigned long smpboot_header_start = (unsigned long) &smpboot_header;

	unsigned long off = smpboot_header_start - start_smp;

	unsigned long actual_smpboot_header = PHYS_BASE + off;

	struct smp_header *s = (struct smp_header *) actual_smpboot_header;

	s->gs_base = percpu_init_for_cpu(cpu);
	s->boot_done = false;

	other_cpu_write(cpu_nr, cpu, cpu);

	sched_init_cpu(cpu);

	cpu_messages_init(cpu);

	s->thread_stack = (unsigned long) get_thread_for_cpu(cpu)->kernel_stack_top;

	apic_set_lapic_id(cpu, lapic_ids[cpu]);

	apic_wake_up_processor(static_cast<uint8_t>(lapic_ids[cpu]), s);

	smp::set_online(cpu);
}

};

extern "C"
void smp_parse_cpus(void *__madt)
{
	ACPI_TABLE_MADT *madt = static_cast<ACPI_TABLE_MADT*>(__madt);
	unsigned int nr_cpus = 0;
	auto first = (ACPI_SUBTABLE_HEADER *) (madt + 1);
	for(ACPI_SUBTABLE_HEADER *i = first; i < (ACPI_SUBTABLE_HEADER*)((char*) madt + madt->Header.Length); i = 
	(ACPI_SUBTABLE_HEADER*)((uint64_t)i + (uint64_t)i->Length))
	{
		if(i->Type == ACPI_MADT_TYPE_LOCAL_APIC)
		{
			ACPI_MADT_LOCAL_APIC *la = (ACPI_MADT_LOCAL_APIC *) i;
			
			assert(smp::lapic_ids.push_back(la->Id) != false);
			nr_cpus++;
		}
	}

	smp::set_number_of_cpus(nr_cpus);
	cpu_messages_init(0);

	/* We're CPU0 and we're online */
	smp::set_online(0);
}

extern "C"
void smp_boot_cpus()
{
	smp::boot_cpus();
}
