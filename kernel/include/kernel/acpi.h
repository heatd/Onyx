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
#ifndef _ACPI_KERNEL_H
#define _ACPI_KERNEL_H
#include <stdint.h>

#define ACPI_PIC_PIC 0
#define ACPI_PIC_IOAPIC 1
#define ACPI_PIC_IOSAPIC 1

int acpi_initialize();
uint32_t acpi_shutdown(void *context);
uint32_t acpi_execute_pic(int value);
int acpi_get_irq_routing_tables();
int acpi_get_irq_routing_for_dev(uint8_t bus, uint8_t device, uint8_t function);

#endif