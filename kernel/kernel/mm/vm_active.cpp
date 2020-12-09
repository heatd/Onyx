/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/vm.h>
#include <onyx/smp.h>
#include <onyx/panic.h>

/* No, I can't stop swearing #ScrewC */
void *vm_create_active_cpus()
{
	auto m = new cpumask;

	if(!m)
		panic("Out of memory allocating active cpus");

	return m;
}
