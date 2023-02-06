/*
 * Copyright (c) 2021 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _PCI_INTERNAL_PCI_BUS_H
#define _PCI_INTERNAL_PCI_BUS_H

#include <stdint.h>

#include <onyx/acpi.h>
#include <onyx/dev.h>
#include <onyx/vector.h>

#include <pci/pci.h>
#include <pci/pcie.h>

namespace pci
{

class pci_root;

enum pci_resource_type
{
    PCI_RSRC_TYPE_IO = 0,
    PCI_RSRC_TYPE_MEM,
    PCI_RSRC_TYPE_MEM64,
    PCI_RSRC_TYPE_MAX
};

struct pci_bus_resource
{
    u64 pci_start;
    u64 size;
    u64 required_alignment;
    pci_resource_type type;
};

class pci_bus : public ::bus
{
protected:
    pci_bus *parent;
    pci_root *parent_root;
    uint8_t nbus;
    pci_bus_resource resources[PCI_RSRC_TYPE_MAX];

    pci_device *enumerate_device(const device_address &addr, pcie_allocation *alloc);
    pcie_allocation *get_alloc() const;

public:
    pci_bus(uint8_t nbus, pci_bus *parent, pci_root *parent_root)
        : bus{"pci"}, parent{parent}, parent_root{parent_root}, nbus{nbus}
    {
        if (parent)
            parent->add_bus(this);
        for (unsigned int i = 0; i < PCI_RSRC_TYPE_MAX; i++)
        {
            resources[i].pci_start = resources[i].size = resources[i].required_alignment = 0;
            resources[i].type = (pci_resource_type) i;
        }
    }

    virtual ~pci_bus() = default;

    pci_root *get_parent_root()
    {
        return parent_root;
    }

    void discover();

    acpi_status route_bus_irqs(acpi_handle bus_object);

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

    pci_bus *find_child_bus_unlocked(uint8_t nbus)
    {
        pci_bus *ret = nullptr;
        for_every_child_bus_unlocked([&](bus *b) -> bool {
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

    /**
     * @brief Calculate the required resources
     * to be assigned to the PCI-PCI bridge.
     *
     */
    void calculate_needed_resources();

    /**
     * @brief Add a resource to the to-be-allocated types
     *
     * @param size Size of the resource
     * @param type Type of the resource
     */
    void add_res(u64 size, pci_resource_type type);

    /**
     * @brief Convert bus resources into a resource request
     *
     * @tparam InsertFunc Function that inserts the bus_resource
     * @param insert
     * @return True on success, else false
     */
    template <typename InsertFunc>
    bool resources_to_res_req(InsertFunc insert)
    {
        for (const auto &res : resources)
        {
            /* Ignore the bus resource if it doesn't exist or is already assigned. */
            if (res.size == 0)
                continue;
            if (res.pci_start != 0)
                continue;
            if (!insert(res))
                return false;
        }

        return true;
    }
};

void add_bus(pci_bus *b);

} // namespace pci

#endif
