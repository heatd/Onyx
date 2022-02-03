/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include "rtl8168.h"

#include <stdio.h>

#include <onyx/dev.h>
#include <onyx/driver.h>

#include <pci/pci.h>

#define RTL_VENDORID 0x10EC

int rtl8168_probe(device *dev_)
{
    auto dev = (pci::pci_device *) dev_;

    auto addr = dev->addr();

    printk("Found suitable rtl8111/rtl8168 device at %04x:%02x:%02x:%02x\n"
           "ID %04x:%04x\n",
           addr.segment, addr.bus, addr.device, addr.function, dev->vid(), dev->did());

    return 0;
}

struct pci::pci_id rtl8168_pci_ids[] = {
    {PCI_ID_DEVICE(RTL_VENDORID, 0x8168, NULL)}, {PCI_ID_DEVICE(RTL_VENDORID, 0x8111, NULL)}, {0}};

struct driver rtl8168_driver = {.name = "rtl8168",
                                .devids = &rtl8168_pci_ids,
                                .probe = rtl8168_probe,
                                .bus_type_node = {&rtl8168_driver}};

int rtl8168_init(void)
{
    pci::register_driver(&rtl8168_driver);
    return 0;
}

MODULE_INIT(rtl8168_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
