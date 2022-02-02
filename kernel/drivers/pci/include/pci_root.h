/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _PCI_INTERNAL_PCI_ROOT_H
#define _PCI_INTERNAL_PCI_ROOT_H

#include <stdint.h>

#include <onyx/acpi.h>
#include <onyx/dev.h>

#include <pci/pci.h>

#include "pci_bus.h"

namespace pci
{

class pci_root : public pci_bus
{
    uint16_t segment_;

public:
    pci_root(uint16_t segment, uint8_t bus_nr) : pci_bus{bus_nr, nullptr, this}, segment_{segment}
    {
    }
    virtual ~pci_root()
    {
    }

    uint16_t get_segment() const
    {
        return segment_;
    }

    void route_irqs(ACPI_HANDLE bus_object);
};

} // namespace pci

#endif
