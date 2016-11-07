/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <kernel/compiler.h>
#include <kernel/pit.h>
#include <drivers/rtc.h>

const size_t max_entropy = 512;
static char entropy_buffer[512];
static size_t current_entropy = 0;
void add_entropy(void *ent, size_t size)
{
	if(current_entropy == max_entropy || current_entropy + size >= max_entropy)
		return;
	memcpy(&entropy_buffer[current_entropy], ent, size);
	current_entropy += size;
}
void get_entropy(char *buf, size_t s)
{
	for(size_t i = 0; i < s; i++)
	{
		while(current_entropy == 0);
		*buf++ = entropy_buffer[0];
		current_entropy--;
		memmove(entropy_buffer, &entropy_buffer[1], current_entropy);
	}
}
void initialize_entropy()
{
	/* Use get_posix_time as entropy, together with the TSC and the PIT */
	uint64_t p = get_posix_time();
	add_entropy(&p, sizeof(uint64_t));
	uint64_t tick = get_tick_count();
	add_entropy(&tick, sizeof(uint64_t));
	uint64_t tsc = rdtsc();
	add_entropy(&tsc, sizeof(uint64_t));
	srand((unsigned int) p << 32);
	for(size_t i = current_entropy; i < max_entropy; i++)
	{
		int r = rand();
		add_entropy(&r, sizeof(int));
	}
	uint16_t uuid[16];
	get_entropy((char*) &uuid, 16);
	printf("UUID: %x:%x:%x:%x\n", uuid[0], uuid[1], uuid[2], uuid[3]);
}