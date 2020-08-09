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

#include <onyx/compiler.h>
#include <onyx/timer.h>
#include <onyx/dev.h>
#include <onyx/random.h>
#include <onyx/process.h>
#include <onyx/clock.h>

#include <drivers/rtc.h>

const size_t max_entropy = PAGE_SIZE * 4;
static char entropy_buffer[PAGE_SIZE * 4] = {0};
struct spinlock entropy_lock;
static size_t current_entropy = 0;

void add_entropy(void *ent, size_t size)
{
	spin_lock(&entropy_lock);
	if(current_entropy == max_entropy || current_entropy + size > max_entropy)
	{}
	else
	{
		memcpy(&entropy_buffer[current_entropy], ent, size);
		current_entropy += size;
	}

	spin_unlock(&entropy_lock);
}

void entropy_refill(void)
{
	unsigned int *buf = (unsigned int*) entropy_buffer;
	size_t nr_refills = max_entropy / sizeof(unsigned int);
	for(size_t i = 0; i < nr_refills; i++)
	{
		*buf++ = clock_get_posix_time() << 28 | get_microseconds() << 24 | ((rdtsc() << 20) ^ rand());
	}

	current_entropy = max_entropy;
}

void get_entropy(char *buf, size_t s)
{
	spin_lock(&entropy_lock);

	for(size_t i = 0; i < s; i++)
	{
		if(current_entropy == 0)
			entropy_refill();
		*buf++ = entropy_buffer[0];
		current_entropy--;
		memmove(entropy_buffer, &entropy_buffer[1], current_entropy);
	}

	spin_unlock(&entropy_lock);
}

size_t ent_read(size_t off, size_t count, void *buffer, struct file *node)
{
	get_entropy((char*) buffer, count);
	return count;
}

void initialize_entropy(void)
{
	/* Use get_posix_time as entropy, together with the TSC */
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
	size_t ret = (size_t) -EINVAL;

	spin_lock(&entropy_lock);

	switch(pool)
	{
		case ENTROPY_POOL_RANDOM:
		{
			ret = random_get_entropy(size, buffer);
			break;
		}

		case ENTROPY_POOL_URANDOM:
		{
			ret = urandom_get_entropy(size, buffer);
			break;
		}
	}

	spin_unlock(&entropy_lock);

	return ret;
}

size_t random_read(size_t offset, size_t sizeofreading, void *buffer, struct file *this)
{
	return get_entropy_from_pool(ENTROPY_POOL_RANDOM, sizeofreading, buffer);
}

size_t urandom_read(size_t offset, size_t sizeofreading, void *buffer, struct file *this)
{
	return get_entropy_from_pool(ENTROPY_POOL_URANDOM, sizeofreading, buffer);
}

void init_random_dev(void)
{
	struct dev *dev = dev_register(0, 0, "random");
	assert(dev);

	dev->fops.read = random_read;
	
	device_show(dev, DEVICE_NO_PATH, 0666);
}

void init_urandom_dev(void)
{
	struct dev *dev = dev_register(0, 0, "urandom");
	assert(dev);
	

	dev->fops.read = urandom_read;
	
	device_show(dev, DEVICE_NO_PATH, 0666);
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
	if(vm_check_pointer(buf, buflen) < 0)
		return -EFAULT;
	return (int) get_entropy_from_pool(ENTROPY_POOL_URANDOM, buflen, buf);
}
