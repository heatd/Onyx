#ifndef _LINUX_ACPI_H
#define _LINUX_ACPI_H

#include <onyx/acpi.h>
#include <linux/device.h>

#include <linux/property.h>

struct acpi_device {
    struct device base;
    struct fwnode_handle fwnode;
};

struct acpi_bus_type {
    const char *name;
    bool (*match)(struct device *dev);
    struct acpi_device *(*find_companion)(struct device *dev);
};

void register_acpi_bus_type(struct acpi_bus_type *type);
void unregister_acpi_bus_type(struct acpi_bus_type *type);

#define to_acpi_device_node(nodep) (container_of(nodep, struct acpi_device, fwnode))

#endif
