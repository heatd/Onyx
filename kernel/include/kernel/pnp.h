/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_PNP_H
#define _KERNEL_PNP_H

#include <kernel/acpi.h>

typedef struct pnpdev
{
	struct pnpdev *next;
	const char *pnp_string;
	ACPI_DEVICE_INFO *acpi_dev;
} pnp_dev_t;
void pnp_register_dev_acpi(ACPI_DEVICE_INFO *dev);
void pnp_find_device(const char *pnpstring);






#endif