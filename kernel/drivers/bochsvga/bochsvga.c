/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <drivers/bochsvga.h>
#include <kernel/log.h>
PCIDevice *bochsvga_dev = NULL;
void bochsvga_init(PCIDevice *dev)
{
	LOG("bochsvga", "initializing\n");
	bochsvga_dev = dev;

	
}