/*
 * Copyright (c) 2021 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/acpi.h>
#include <onyx/driver.h>

#include "uart8250.h"

#include <onyx/memory.hpp>

static acpi_dev_id uart8250_acpi_devids[] = {{"PNP0501"}, {"PNP0500"}, {nullptr}};

/**
 * @brief Probe the device and try to initialise hardware
 *
 * @param fake_dev Pointer to the base device
 * @return 0 on success, negative on failure.
 */
int uart8250_acpi_probe(device *dev);

static driver uart8250_acpi_driver = {
    .name = "uart8250-acpi",
    .devids = (void *) uart8250_acpi_devids,
    .probe = uart8250_acpi_probe,
    .bus_type_node = {&uart8250_acpi_driver},
};

/**
 * @brief Probe the device and try to initialise hardware
 *
 * @param fake_dev Pointer to the base device
 * @return 0 on success, negative on failure.
 */
int uart8250_acpi_probe(device *fake_dev)
{
    auto dev = (acpi_device *) fake_dev;

    // Find IRQ, IO resources
    auto irq_rc = dev->get_resource(DEV_RESOURCE_FLAG_IRQ);

    if (!irq_rc)
        return -1;

    auto io_resource = dev->get_resource(DEV_RESOURCE_FLAG_IO_PORT);

    // Note: IO resources should need to have a size of 8 at least
    // but some, like qemu's uart8250, don't. weird.
    if (!io_resource)
        return -1;

    unique_ptr<uart8250_port> port = make_unique<uart8250_port>(
        io_resource->start(), static_cast<unsigned int>(irq_rc->start()), dev);

    if (!port)
        return -1;

    if (!port->init())
        return -1;

    dev->priv = port.release();

    return 0;
}

int uart8250_acpi_init()
{
    acpi_bus_register_driver(&uart8250_acpi_driver);
    return 0;
}

DRIVER_INIT(uart8250_acpi_init);
