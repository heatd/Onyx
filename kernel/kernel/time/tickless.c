/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>

#include <onyx/cpu.h>
#include <onyx/timer.h>

void tickless_init(void)
{
	//struct processor *p = get_processor_data();
	struct clocksource *c = get_main_clock();
	printk("Name: %s\n", c->name);
}