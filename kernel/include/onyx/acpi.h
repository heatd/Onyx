/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ACPI_KERNEL_H
#define _ACPI_KERNEL_H

#include <stdint.h>
#include <acpica/acpi.h>

#include <onyx/dev.h>

struct acpi_processor
{
	ACPI_HANDLE object;
#ifdef __x86_64__
	uint32_t apic_id;
#endif
};

struct acpi_device
{
	struct device dev; /* Base object (or class if you prefer) */
	ACPI_HANDLE object;
	ACPI_DEVICE_INFO *info;
	ACPI_RESOURCE *resources;
};

struct acpi_dev_id
{
	const char *devid;
};

#define ACPI_PIC_PIC 0
#define ACPI_PIC_IOAPIC 1
#define ACPI_PIC_IOSAPIC 1

#define ACPI_POWER_STATE_D0	0
#define ACPI_POWER_STATE_D1	1
#define ACPI_POWER_STATE_D2	2
#define ACPI_POWER_STATE_D3	3

#ifdef __cplusplus
extern "C"{
#endif

uintptr_t acpi_get_rsdp(void);

int acpi_initialize(void);

uint32_t acpi_shutdown(void);

uint32_t acpi_execute_pic(int value);

int acpi_get_irq_routing_tables();

int acpi_get_irq_routing_for_dev(uint8_t bus, uint8_t device,
	uint8_t function);

struct acpi_processor *acpi_enumerate_cpus(void);

struct acpi_device *acpi_get_device(const char *id);

unsigned int acpi_suspend(void);

int acpi_get_irq_routing_info(struct bus *bus);

void acpi_bus_register_driver(struct driver *driver);

ACPI_RESOURCE *acpi_get_resource(struct acpi_device *device, uint32_t type,
	unsigned int index);

extern struct clocksource acpi_timer_source;

#ifdef __cplusplus
}
#endif

#endif
