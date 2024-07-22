/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _PCIE_H
#define _PCIE_H

#include <stdbool.h>
#include <stdint.h>

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

int pcie_get_mcfg(void);
bool pcie_is_enabled(void);
int pcie_init(void);
pcie_allocation *find_alloc_for_root(uint16_t segment, uint8_t nbus);

} // namespace pci

#endif
