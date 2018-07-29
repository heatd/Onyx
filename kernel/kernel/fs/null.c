/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>

#include <onyx/dev.h>
#include <onyx/compiler.h>
#include <onyx/panic.h>

size_t null_write(size_t offset, size_t count, void *buf, struct inode *n)
{
	/* While writing to /dev/null, everything gets discarded. It's basically a no-op. */
	UNUSED(offset);
	UNUSED(count);
	UNUSED(buf);
	UNUSED(n);
	return count;
}

void null_init(void)
{	
	struct dev *min = dev_register(0, 0, "null");
	if(!min)
		panic("Could not create a device ID for /dev/null!\n");

	min->fops.write = null_write;
	
	device_show(min, DEVICE_NO_PATH);
}
