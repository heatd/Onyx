/*
 * Copyright (c) 2021 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _PCI_INTERNAL_PCI_ROOT_H
#define _PCI_INTERNAL_PCI_ROOT_H

#include <stdint.h>

#include <onyx/acpi.h>
#include <onyx/dev.h>
#include <onyx/vector.h>

#include <pci/pci.h>

#include "pci_bus.h"

namespace pci
{

#define PCI_ROOT_RSRC_IO    (1U << 0)
#define PCI_ROOT_RSRC_MEM   (1U << 1)
#define PCI_ROOT_RSRC_MEM64 (1U << 2)

/**
 * @brief Represents a PCI root host bridge resource
 *
 */
struct pci_root_resource
{
    u64 pci_start;
    u64 cpu_start;
    u64 size;
    unsigned int flags;

    pci_root_resource(u64 pci_start, u64 cpu_start, u64 size, unsigned int flags)
        : pci_start{pci_start}, cpu_start{cpu_start}, size{size}, flags{flags}
    {
    }

    pci_root_resource() = default;
};

class pci_root : public pci_bus
{
    uint16_t segment_;
    u8 next_bus_allocation_;
    cul::vector<pci_root_resource> host_bridge_rsrc;

    expected<pci_root_resource, int> carve_resource(u64 alignment, u64 size,
                                                    pci_resource_type type);

public:
    pci_root(uint16_t segment, uint8_t bus_nr)
        : pci_bus{bus_nr, nullptr, this}, segment_{segment}, next_bus_allocation_{
                                                                 static_cast<u8>(bus_nr + 1)}
    {
    }

    virtual ~pci_root() = default;

    uint16_t get_segment() const
    {
        return segment_;
    }

    /**
     * @brief Allocate a bus number for a PCI-PCI bridge
     *
     * @return Bus number
     */
    u8 allocate_bus_nr();

    /**
     * @brief Retrieve the last bus number assigned
     *
     * @return Last bus number assigned
     */
    u8 last_bus_nr() const;

    void route_irqs(acpi_handle bus_object);

    /**
     * @brief Add a resource to this root's host bridge
     *
     * @param resource PCI resource to add
     * @return 0 on success, negative error codes
     */
    int add_resource(pci_root_resource&& resource);

    /**
     * @brief Assign resources to devices and bridges
     *
     */
    void assign_resources();
};

} // namespace pci

#endif
