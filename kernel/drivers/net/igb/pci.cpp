/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/mm/slab.h>
#include <onyx/module.h>

#include <pci/pci.h>

#include "e1000.h"

static struct pci::pci_id igb_pci_ids[] = {
    {PCI_ID_DEVICE(INTEL_VENDOR, E1000_I210, NULL)},
    {PCI_ID_DEVICE(INTEL_VENDOR, 0x10c9, NULL)},
    {0},
};

static int igb_pci_probe(struct device *__dev)
{
    pci::pci_device *dev = (pci::pci_device *) __dev;

    dev_info(__dev, "Found suitable igb device with ID %04x:%04x\n", dev->vid(), dev->did());

    char *mem_space = (char *) dev->map_bar(0, VM_NOCACHE);
    if (!mem_space)
    {
        dev_err(__dev,
                "Sorry! This driver only supports igb register access through MMIO, "
                "and sadly your card needs the legacy I/O port method of accessing registers\n");
        return -1;
    }

    struct igb_dev *nicdev = (struct igb_dev *) kmalloc(sizeof(*nicdev), GFP_KERNEL);
    if (!nicdev)
    {
        /* TODO: Unmap mem_space */
        return -1;
    }

    dev->enable_device();
    dev->enable_irq();
    dev->enable_busmastering();

    nicdev->dev = __dev;
    nicdev->regs = (volatile char *) mem_space;
    nicdev->irq_nr = dev->get_intn();
    return igb_probe(nicdev);
}

void igb_enable_interrupts(struct igb_dev *dev)
{
    pci::pci_device *pdev = (pci::pci_device *) dev->dev;

    if (WARN_ON(pci_alloc_irqs(pdev, 1, 1, PCI_IRQ_MSI | PCI_IRQ_INTX)))
        return;
    if (WARN_ON(pci_install_irq(pdev, 0, igb_irq, IRQ_FLAG_REGULAR, dev, "igb%d", 0)))
        return;

    igb_read(REG_ICR, dev);
    igb_write(REG_IMS, IMS_TXDW | IMS_RXT0, dev);
    igb_write(REG_IAM, IMS_TXDW | IMS_RXT0, dev);
}

static struct driver igb_driver = {
    .name = "igb",
    .devids = &igb_pci_ids,
    .probe = igb_pci_probe,
    .bus_type_node = {&igb_driver},
};

static int igb_init(void)
{
    pci::register_driver(&igb_driver);
    return 0;
}

MODULE_INIT(igb_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_GPL2);
MODULE_AUTHOR("Pedro Falcato");
