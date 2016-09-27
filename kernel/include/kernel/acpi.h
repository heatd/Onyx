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
#ifndef _ACPI_KERNEL_H
#define _ACPI_KERNEL_H
#include <stdint.h>

int acpi_initialize();
uint32_t acpi_shutdown(void *context);








#endif