/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/device_tree.h>
#include <onyx/driver.h>

#include "pl011.h"

int pl011_dt_probe(device *fake_dev)
{
    auto dev = (device_tree::node *) fake_dev;

    // Find IRQ, IO resources
    auto irq_rc = dev->get_resource(DEV_RESOURCE_FLAG_IRQ);
    if (!irq_rc)
        return -1;

    auto mmio_resource = dev->get_resource(DEV_RESOURCE_FLAG_MEM);
    if (!mmio_resource)
        return -1;

    volatile void *r = mmiomap((void *) mmio_resource->start(), mmio_resource->size(),
                               VM_WRITE | VM_READ | VM_NOCACHE);

    unique_ptr<pl011_dev> device =
        make_unique<pl011_dev>(r, static_cast<unsigned int>(irq_rc->start()), dev);

    if (!device)
        return -1;

    if (!device->init())
        return -1;

    dev->priv = device.release();

    return 0;
}

static const char *pl011_compatible_ids[] = {"arm,pl011", nullptr};

static driver pl011_dt = {
    .name = "pl011-dt",
    .devids = pl011_compatible_ids,
    .probe = pl011_dt_probe,
    .bus_type_node = &pl011_dt,
};

int pl011_dt_init()
{
    device_tree::register_driver(&pl011_dt);
    return 0;
}

DRIVER_INIT(pl011_dt_init);
