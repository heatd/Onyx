/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <kernel/compiler.h>
#include <kernel/pit.h>
#include <kernel/timer.h>
#include <kernel/dev.h>
#include <kernel/random.h>
#include <kernel/process.h>

#include <drivers/rtc.h>

const size_t max_entropy = PAGE_SIZE * 4;
static char entropy_buffer[PAGE_SIZE * 4] = {0};
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
void initialize_entropy(void)
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
}
void entropy_refill(void)
{
	unsigned int *buf = (unsigned int*) entropy_buffer;
	size_t nr_refills = max_entropy / sizeof(unsigned int);
	for(size_t i = 0; i < nr_refills; i++)
	{
		*buf++ = get_posix_time() << 28 | get_microseconds() << 24 | rdtsc() << 20 | rand();
	}
}
size_t random_get_entropy(size_t size, void *buffer)
{
	unsigned char *buf = buffer;
	size_t to_read = size;
	while(to_read)
	{
		if(signal_is_pending())
			return -EINTR;
		if(current_entropy)
		{
			size_t r = current_entropy > to_read ? to_read : current_entropy;
			memcpy(buf, entropy_buffer, r);
			buf += r;
			to_read -= r;
		}
	}
	return size;
}
size_t urandom_get_entropy(size_t size, void *buffer)
{
	unsigned char *buf = buffer;
	size_t to_read = size;
	while(to_read)
	{
		if(signal_is_pending())
			return -EINTR;
		if(current_entropy)
		{
			size_t r = current_entropy > to_read ? to_read : current_entropy;
			memcpy(buf, entropy_buffer, r);
			buf += r;
			to_read -= r;
		}
		else
		{
			entropy_refill();
		}
	}
	return size;
}
size_t get_entropy_from_pool(int pool, size_t size, void *buffer)
{
	assert(pool == ENTROPY_POOL_RANDOM || pool == ENTROPY_POOL_URANDOM);
	switch(pool)
	{
		case ENTROPY_POOL_RANDOM:
		{
			return random_get_entropy(size, buffer);
		}
		case ENTROPY_POOL_URANDOM:
		{
			return urandom_get_entropy(size, buffer);
		}
	}
	return -EINVAL;
}
size_t random_read(int flags, size_t offset, size_t sizeofreading, void *buffer, vfsnode_t *this)
{
	return get_entropy_from_pool(ENTROPY_POOL_RANDOM, sizeofreading, buffer);
}
size_t urandom_read(int flags, size_t offset, size_t sizeofreading, void *buffer, vfsnode_t *this)
{
	return get_entropy_from_pool(ENTROPY_POOL_URANDOM, sizeofreading, buffer);
}
void init_random_dev(void)
{
	struct minor_device *dev = dev_register(0, 0);
	assert(dev);
	dev->fops = malloc(sizeof(struct file_ops));
	assert(dev->fops);
	dev->fops->read = random_read;
	vfsnode_t *file = creat_vfs(slashdev, "random", 0666);
	assert(file);
	file->type = VFS_TYPE_CHAR_DEVICE;
	file->dev = dev->majorminor;
}
void init_urandom_dev(void)
{
	struct minor_device *dev = dev_register(0, 0);
	assert(dev);
	dev->fops = malloc(sizeof(struct file_ops));
	assert(dev->fops);
	dev->fops->read = urandom_read;
	vfsnode_t *file = creat_vfs(slashdev, "urandom", 0666);
	assert(file);
	file->type = VFS_TYPE_CHAR_DEVICE;
	file->dev = dev->majorminor;
}
void entropy_init_dev(void)
{
	init_random_dev();
	init_urandom_dev();
}
unsigned int get_random_int(void)
{
	unsigned int result = rand();
	result |= (get_tick_count() | get_microseconds()) + rdtsc();
	return result;
}
int sys_getrandom(void *buf, size_t buflen, unsigned int flags)
{
	if(vmm_check_pointer(buf, buflen) < 0)
		return -EFAULT;
	return (int) get_entropy_from_pool(ENTROPY_POOL_URANDOM, buflen, buf);
}
