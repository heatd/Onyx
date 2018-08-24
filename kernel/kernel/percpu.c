/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <assert.h>
#include <stdio.h>

#include <onyx/percpu.h>
#include <onyx/cpu.h>

unsigned char *percpu_master_copy = (unsigned char *) &__percpu_start;

void setup_percpu(void)
{
	int nr_cpus = get_nr_cpus();

	size_t percpu_master_copy_size = (uintptr_t) &__percpu_end - (uintptr_t) &__percpu_start;

	for(int i = 0; i < nr_cpus; i++)
	{
		struct processor *p = get_processor_data_for_cpu(i);
		assert(p != NULL);
		p->percpu_copy = zalloc(percpu_master_copy_size);
		assert(p != NULL);
	}
}

void *__do_get_per_cpu(uintptr_t offset)
{
	struct processor *p = get_processor_data();
	if(!p)
		return percpu_master_copy + offset;

	return p->percpu_copy + offset;
}
