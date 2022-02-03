/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _PCI_INTERNAL_PCI_BUS_H
#define _PCI_INTERNAL_PCI_BUS_H

#include <stdint.h>

#include <onyx/acpi.h>
#include <onyx/dev.h>

#include <pci/pci.h>
#include <pci/pcie.h>

namespace pci
{

class pci_root;

class pci_bus : public ::bus
{
protected:
    pci_bus *parent;
    pci_root *parent_root;
    uint8_t nbus;

    pci_device *enumerate_device(const device_address &addr, pcie_allocation *alloc);
    pcie_allocation *get_alloc() const;

public:
    pci_bus(uint8_t nbus, pci_bus *parent, pci_root *parent_root)
        : bus{"pci"}, parent{parent}, parent_root{parent_root}, nbus{nbus}
    {
        if (parent)
            parent->add_bus(this);
    }

    virtual ~pci_bus()
    {
    }

    void discover();

    ACPI_STATUS route_bus_irqs(ACPI_HANDLE bus_object);

    uint8_t get_bus_nr() const
    {
        return nbus;
    }

    pci_device *find_device(uint8_t dev, uint8_t function)
    {
        pci_device *ret = nullptr;
        for_every_device([&](device *dev_) -> bool {
            pci_device *pdev = (pci_device *) dev_;

            auto addr = pdev->addr();

            if (addr.device == dev && addr.function == function)
            {
                // We can stop here(note false = stop)
                ret = pdev;
                return false;
            }

            return true;
        });

        return ret;
    }

    pci_bus *find_child_bus(uint8_t nbus)
    {
        pci_bus *ret = nullptr;
        for_every_child_bus([&](bus *b) -> bool {
            pci_bus *pbus = (pci_bus *) b;

            if (pbus->get_bus_nr() == nbus)
            {
                // We can stop here(note false = stop)
                ret = pbus;
                return false;
            }

            return true;
        });

        return ret;
    }
};

void add_bus(pci_bus *b);

} // namespace pci

#endif
