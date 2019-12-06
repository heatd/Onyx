/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>

#include <onyx/smp.h>
#include <onyx/bitmap.h>
#include <onyx/percpu.h>
#include <onyx/paging.h>

extern unsigned char _start_smp;
extern unsigned char _end_smp;

extern "C"
{

PER_CPU_VAR(unsigned int cpu_nr) = 0;

unsigned int get_cpu_nr()
{
	if(!percpu_initialized())
		return 0;
	return get_per_cpu(cpu_nr);
}

};

namespace smp
{

static Bitmap<0, false> bt;
unsigned int nr_cpus = 0;
unsigned int online_cpus = 0;
constexpr unsigned long smp_trampoline_phys = 0x0;

void set_number_of_cpus(unsigned int nr)
{
	bt.SetSize(nr);
	assert(bt.AllocateBitmap() == true);
	nr_cpus = nr;
}

void set_online(unsigned int cpu)
{
	bt.SetBit(cpu);
	online_cpus++;
}

void boot_cpus()
{
	printf("smpboot: booting cpus\n");
	memcpy((void*) (PHYS_BASE + (uintptr_t) smp_trampoline_phys), &_start_smp,
		(uintptr_t) &_end_smp - (uintptr_t) &_start_smp);
	
	for(unsigned int i = 0; i < nr_cpus; i++)
	{
		if(!bt.IsSet(i))
		{
			boot(i);
		}
	}

	printf("smpboot: done booting cpus, %u online\n", online_cpus);
}

unsigned int get_online_cpus()
{
	return online_cpus;
}

}