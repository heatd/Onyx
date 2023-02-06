/*
 * Copyright (c) 2021 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _PCI_INTERNAL_CONFIG_ACCESSOR_H
#define _PCI_INTERNAL_CONFIG_ACCESSOR_H

#include <stdint.h>

#include <pci/pci.h>
#include <pci/pcie.h>

namespace pci
{

class config_accessor
{
public:
    virtual uint64_t read(const device_address &addr, uint16_t off, size_t size,
                          const pcie_allocation *alloc = nullptr) = 0;
    virtual void write(const device_address &addr, uint64_t value, uint16_t off, size_t size,
                       const pcie_allocation *alloc = nullptr) = 0;
};

void set_accessor(config_accessor *a);

} // namespace pci

#endif
