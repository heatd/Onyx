/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_PNP_H
#define _KERNEL_PNP_H

#include <onyx/acpi.h>

typedef struct pnpdev
{
	struct pnpdev *next;
	const char *pnp_string;
	ACPI_DEVICE_INFO *acpi_dev;
} pnp_dev_t;
void pnp_register_dev_acpi(ACPI_DEVICE_INFO *dev);
void pnp_find_device(const char *pnpstring);

#endif
