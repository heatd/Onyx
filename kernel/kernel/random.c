/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <kernel/compiler.h>
#include <kernel/pit.h>
#include <kernel/timer.h>
#include <kernel/dev.h>

#include <drivers/rtc.h>

const size_t max_entropy = 512;
static char entropy_buffer[512];
static size_t current_entropy = 0;
void add_entropy(void *ent, size_t size)
{
	if(current_entropy == max_entropy || current_entropy + size > max_entropy)
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
size_t ent_read(size_t off, size_t count, void *buffer, vfsnode_t *node)
{
	get_entropy((char*) buffer, count);
	return count;
}
void initialize_entropy()
{
	/* Use get_posix_time as entropy, together with the TSC and the PIT */
	uint64_t p = get_posix_time_early();
	add_entropy(&p, sizeof(uint64_t));
	uint64_t tsc = rdtsc();
	add_entropy(&tsc, sizeof(uint32_t));
	srand((unsigned int) (tsc | ~p));
	for(size_t i = current_entropy; i < max_entropy; i+= sizeof(int))
	{
		int r = rand();
		add_entropy(&r, sizeof(int));
	}
	/*vfsnode_t *n = creat_vfs(slashdev, "/dev/random", 0666);
	n->type = VFS_TYPE_BLOCK_DEVICE;
	n->read = ent_read;*/
}
