/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/device_tree.h>

#include <onyx/hwregister.hpp>

class plic_chip
{
private:
    mmio_range plic_base;

public:
    plic_chip(device_tree::node *node);

    DEFINE_MMIO_RW_FUNCTIONS(plic_base);
};

plic_chip *irqchip = nullptr;

int plic_probe(device *dev)
{
    return 0;
}

static const char *plic_compatible_ids[] = {"sifive,plic-1.0.0", "riscv,plic0", nullptr};

static driver plic_driver = {
    .name = "plic",
    .devids = plic_compatible_ids,
    .probe = plic_probe,
    .bus_type_node = &plic_driver,
};

void plic_init()
{
    device_tree::register_driver(&plic_driver);
}
