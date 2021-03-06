/*
* Copyright (c) 2016-2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/dev.h>
#include <onyx/panic.h>
#include <onyx/compiler.h>
#include <onyx/vm.h>
#include <onyx/init.h>

size_t zero_read(size_t offset, size_t count, void *buf, file *f)
{
	/* While reading from /dev/zero, all you read is zeroes. Just memset the buf. */
	if(user_memset(buf, 0, count) < 0)
		return errno = EFAULT, -1;

	return count;
}

size_t zero_write(size_t offset, size_t len, void *buf, file *f)
{
	/* Writes behave like /dev/null */
	return len;
}

void *zero_mmap(struct vm_region *area, struct file *node)
{
	if(vm_region_setup_backing(area, area->pages, false) < 0)
		return nullptr;

	vm_make_anon(area);

	return (void *) area->base;
}

void zero_init(void)
{	
	struct dev *min = dev_register(0, 0, "zero");
	if(!min)
		panic("Could not create a device ID for /dev/zero!\n");
	
	memset(&min->fops, 0, sizeof(file_ops));

	min->fops.read = zero_read;
	min->fops.mmap = zero_mmap;
	min->fops.write = zero_write;
	
	device_show(min, DEVICE_NO_PATH, 0666);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(zero_init);
