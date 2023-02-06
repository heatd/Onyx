/*
 * Copyright (c) 2017 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PCI_PCIE_H
#define _ONYX_PCI_PCIE_H

#include <stdbool.h>
#include <stdint.h>

#include <onyx/types.h>

struct pcie_allocation
{
    /* Mapping of the pcie allocation's configuration address space */
    volatile void *address;
    /* Segment number */
    uint16_t segment;
    /* Start and end buses */
    uint8_t start_bus, end_bus;
};

namespace pci
{

int pcie_get_mcfg();
bool pcie_is_enabled();
int pcie_init();
pcie_allocation *find_alloc_for_root(uint16_t segment, uint8_t nbus);
int add_ecam(u16 segment, u16 start_bus, u16 end_bus, u64 mmio_start);

} // namespace pci

#endif
