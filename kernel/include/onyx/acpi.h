/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_ACPI_H
#define _ONYX_ACPI_H

#include <stdint.h>

#include <onyx/dev.h>

#include <acpica/acpi.h>

struct acpi_processor
{
    acpi_handle object;
#ifdef __x86_64__
    uint32_t apic_id;
#endif
};

struct acpi_device : public device
{
    acpi_handle object;
    acpi_device_info *info;
    acpi_resource *resources;

    acpi_device(const char *name, struct bus *b, device *parent, acpi_handle obj,
                acpi_device_info *info, acpi_resource *rsrc)
        : device{name, b, parent}, object{obj}, info{info}, resources{rsrc}
    {
    }
};

struct acpi_dev_id
{
    const char *devid;
};

#define ACPI_PIC_PIC     0
#define ACPI_PIC_IOAPIC  1
#define ACPI_PIC_IOSAPIC 1

#define ACPI_POWER_STATE_D0 0
#define ACPI_POWER_STATE_D1 1
#define ACPI_POWER_STATE_D2 2
#define ACPI_POWER_STATE_D3 3

uintptr_t acpi_get_rsdp(void);

int acpi_initialize(void);

uint32_t acpi_shutdown(void);

uint32_t acpi_execute_pic(int value);

int acpi_get_irq_routing_tables();

struct acpi_processor *acpi_enumerate_cpus(void);

struct acpi_device *acpi_get_device(const char *id);

unsigned int acpi_suspend(void);

void acpi_bus_register_driver(struct driver *driver);

acpi_resource *acpi_get_resource(struct acpi_device *device, uint32_t type, unsigned int index);
void acpi_set_rsdp(uintptr_t root_pointer);

extern struct clocksource acpi_timer_source;

namespace acpi
{

using find_root_pci_bus_t = int (*)(uint16_t seg, uint8_t nbus, acpi_handle bus);
int find_root_pci_buses(find_root_pci_bus_t callback);
int route_irqs(bus *bus);
bool is_enabled();

#ifndef CONFIG_ACPI
inline bool is_enabled()
{
    return false;
}
#endif

} // namespace acpi

#endif
