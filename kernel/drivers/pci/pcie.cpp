/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <onyx/acpi.h>
#include <onyx/dev.h>
#include <onyx/log.h>
#include <onyx/vector.h>

#include <pci/pci.h>
#include <pci/pcie.h>

#include "include/config_accessor.h"

namespace pci
{

ACPI_TABLE_MCFG *mcfg = nullptr;
cul::vector<pcie_allocation> allocations;

pcie_allocation *find_alloc_for_root(uint16_t segment, uint8_t nbus)
{
    for (auto &a : allocations)
    {
        if (a.segment != segment)
            continue;

        if (a.start_bus > nbus)
            continue;

        if (a.end_bus < nbus)
            continue;

        return &a;
    }

    return nullptr;
}

int pcie_get_mcfg(void)
{
    ACPI_STATUS st;
    if (ACPI_FAILURE((st = AcpiGetTable((char *) "MCFG", 0, (ACPI_TABLE_HEADER **) &mcfg))))
    {
        printf("pcie: MCFG not found - proceeding with conventional pci.\n");
        return 0;
    }

    return 0;
}

bool pcie_is_enabled(void)
{
    return mcfg ? true : false;
}

struct pcie_address
{
    uint8_t bus;
    uint8_t device;
    uint8_t function;
    const pcie_allocation *alloc;
    uint16_t offset;
};

static inline uint32_t __pcie_config_read_dword(const pcie_address &addr)
{
    uintptr_t ptr = (uintptr_t) addr.alloc->address + ((addr.bus - addr.alloc->start_bus) << 20 |
                                                       addr.device << 15 | addr.function << 12);
    volatile uint32_t *data = (volatile uint32_t *) (ptr + addr.offset);

    return *data;
}

static inline void __pcie_config_write_dword(const pcie_address &addr, uint32_t data)
{
    uintptr_t ptr = (uintptr_t) addr.alloc->address + ((addr.bus - addr.alloc->start_bus) << 20 |
                                                       addr.device << 15 | addr.function << 12);
    volatile uint32_t *uptr = (volatile uint32_t *) (ptr + addr.offset);

    *uptr = data;
}

void __pcie_config_write_byte(pcie_address &addr, uint8_t data)
{
    uint16_t aligned_offset = addr.offset & -4;
    uint16_t write_offset = addr.offset - aligned_offset;
    uint16_t write_mask = 0xff << (write_offset * 8);
    addr.offset = aligned_offset;
    uint32_t dword = __pcie_config_read_dword(addr);

    dword = (dword & ~write_mask) | (uint32_t) data << (write_offset * 8);

    __pcie_config_write_dword(addr, dword);
}

uint8_t __pcie_config_read_byte(pcie_address &addr)
{
    uint16_t aligned_offset = addr.offset & -4;
    uint16_t byte_shift = addr.offset - aligned_offset;
    addr.offset = aligned_offset;
    uint32_t dword = __pcie_config_read_dword(addr);

    return ((dword >> (byte_shift * 8)) & 0xff);
}

uint16_t __pcie_config_read_word(pcie_address &addr)
{
    uint16_t ret = 0;
    uint16_t aligned_off = addr.offset & -4;
    uint16_t byte_shift = addr.offset - aligned_off;

    addr.offset = aligned_off;

    uint32_t dword = __pcie_config_read_dword(addr);

    ret = (dword >> (byte_shift * 8));

    return ret;
}

void __pcie_config_write_word_aligned(const pcie_address &addr, uint16_t data)
{
    uintptr_t ptr = (uintptr_t) addr.alloc->address + ((addr.bus - addr.alloc->start_bus) << 20 |
                                                       addr.device << 15 | addr.function << 12);
    volatile uint16_t *uptr = (volatile uint16_t *) (ptr + addr.offset);

    *uptr = data;
}

void __pcie_config_write_word(pcie_address &addr, uint16_t data)
{
    uint8_t aligned_offset = addr.offset & -4;
    uint8_t bshift = addr.offset - aligned_offset;

    if (aligned_offset == addr.offset)
    {
        /* For some reason, we need to do this for linux's
         * i915 driver's GVT to accept PCI config space writes
         * I guess this is an optimization too.
         */
        __pcie_config_write_word_aligned(addr, data);
        return;
    }

    uint32_t byte_mask = (uint32_t) 0xffff << (bshift * 8);
    addr.offset = aligned_offset;
    uint32_t dword = __pcie_config_read_dword(addr);
    dword = (dword & ~byte_mask) | (data << (bshift * 8));
    __pcie_config_write_dword(addr, dword);
}

uint64_t pcie_read_config(pcie_address &addr, uint16_t off, size_t size)
{
    uint64_t val = -1;
    addr.offset = off;

    switch (size)
    {
    case sizeof(uint8_t):
        val = __pcie_config_read_byte(addr);
        break;
    case sizeof(uint16_t):
        val = __pcie_config_read_word(addr);
        break;
    case sizeof(uint32_t):
        val = __pcie_config_read_dword(addr);
        break;
    case sizeof(uint64_t):
        val = __pcie_config_read_dword(addr);
        addr.offset += 4;
        val |= (uint64_t) __pcie_config_read_dword(addr) << 32;
        break;
    }

    return val;
}

void pcie_write_config(pcie_address &addr, uint64_t value, uint16_t off, size_t size)
{
    addr.offset = off;

    switch (size)
    {
    case sizeof(uint8_t):
        __pcie_config_write_byte(addr, (uint8_t) value);
        break;
    case sizeof(uint16_t):
        __pcie_config_write_word(addr, (uint16_t) value);
        break;
    case sizeof(uint32_t):
        __pcie_config_write_dword(addr, (uint32_t) value);
        break;
    case sizeof(uint64_t):
        __pcie_config_write_byte(addr, (uint32_t) value);
        addr.offset += 4;
        __pcie_config_write_dword(addr, (uint32_t) (value >> 32));
        break;
    default:
        INFO("pcie", "pcie_write_device_from_segment: Invalid size\n");
        return;
    }
}

const pcie_allocation *find_alloc_for_address(const device_address &addr)
{
    for (auto &a : allocations)
    {
        if (a.segment != addr.segment)
            continue;
        if (addr.bus < a.start_bus)
            continue;
        if (addr.bus > a.end_bus)
            continue;
        return &a;
    }

    return nullptr;
}

class pcie_accessor : public config_accessor
{
    uint64_t read(const device_address &addr, uint16_t off, size_t size,
                  const pcie_allocation *alloc = nullptr) override
    {
        pcie_address paddr;
        paddr.bus = addr.bus;
        paddr.device = addr.device;
        paddr.function = addr.function;
        paddr.alloc = alloc;
        if (!alloc)
            paddr.alloc = find_alloc_for_address(addr);

        assert(paddr.alloc != nullptr);

        return pcie_read_config(paddr, off, size);
    }

    void write(const device_address &addr, uint64_t value, uint16_t off, size_t size,
               const pcie_allocation *alloc = nullptr) override
    {
        pcie_address paddr;
        paddr.bus = addr.bus;
        paddr.device = addr.device;
        paddr.function = addr.function;
        paddr.alloc = alloc;
        if (!alloc)
            paddr.alloc = find_alloc_for_address(addr);

        assert(paddr.alloc != nullptr);

        return pcie_write_config(paddr, value, off, size);
    }
};

pcie_accessor pcie_access;

int pcie_init(void)
{
    assert(pcie_is_enabled() == true);
    /*
     * If we have PCIe, the MCFG table is passed through acpi to us.
     * To read every MCFG allocation, we get the end of the table. The allocations
     * start there, and there are x number of them
     */
    ACPI_MCFG_ALLOCATION *alloc = (ACPI_MCFG_ALLOCATION *) (mcfg + 1);
    size_t nr_allocs =
        (mcfg->Header.Length - sizeof(ACPI_TABLE_MCFG)) / sizeof(ACPI_MCFG_ALLOCATION);
    while (nr_allocs--)
    {
        pcie_allocation allocation;
        /* Failing to allocate enough memory here is pretty much a system failure */

        unsigned int nr_buses = alloc->EndBusNumber - alloc->StartBusNumber;
        size_t size = nr_buses << 20;

        allocation.address =
            mmiomap((void *) alloc->Address, size, VM_WRITE | VM_NOEXEC | VM_NOCACHE);

        if (!allocation.address)
            return -ENOMEM;

        allocation.segment = alloc->PciSegment;
        allocation.start_bus = alloc->StartBusNumber;
        allocation.end_bus = alloc->EndBusNumber;

        if (!allocations.push_back(cul::move(allocation)))
        {
            vm_munmap(&kernel_address_space, (void *) allocation.address, size);
            return -ENOMEM;
        }

        ++alloc;
    }

    set_accessor(&pcie_access);

    return 0;
}

} // namespace pci
