/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <onyx/compiler.h>
#include <onyx/panic.h>

#include "../include/config_accessor.h"

namespace pci
{

constexpr uint16_t CONFIG_ADDRESS = 0xcf8;
constexpr uint16_t CONFIG_DATA = 0xcfc;
struct spinlock pci_lock;

// TODO: Clean all this up

void __pci_write_qword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint64_t data)
{
    uint32_t address;
    uint32_t lbus = (uint32_t) bus;
    uint32_t lslot = (uint32_t) slot;
    uint32_t lfunc = (uint32_t) func;

    /* create configuration address */
    address = (uint32_t) ((lbus << 16) | (lslot << 11) | (lfunc << 8) | (offset & 0xfc) |
                          ((uint32_t) 0x80000000));

    scoped_lock g{pci_lock};
    /* write out the address */
    outl(CONFIG_ADDRESS, address);
    /* Write out the lower half of the data */
    outl(CONFIG_DATA, data & 0xFFFFFFFF);
    address = (uint32_t) ((lbus << 16) | (lslot << 11) | (lfunc << 8) | ((offset + 4) & 0xfc) |
                          ((uint32_t) 0x80000000));

    /* write out the address */
    outl(CONFIG_ADDRESS, address);
    outl(CONFIG_DATA, data & 0xFFFFFFFF00000000);
}

uint32_t __pci_config_read_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset)
{
    uint32_t address;
    uint32_t lbus = (uint32_t) bus;
    uint32_t lslot = (uint32_t) slot;
    uint32_t lfunc = (uint32_t) func;
    uint32_t tmp = 0;

    address = (uint32_t) ((lbus << 16) | (lslot << 11) | (lfunc << 8) | (offset & 0xfc) |
                          ((uint32_t) 0x80000000));

    scoped_lock g{pci_lock};
    /* write out the address */
    outl(CONFIG_ADDRESS, address);
    /* read in the data */
    tmp = inl(CONFIG_DATA);
    return tmp;
}

__attribute__((no_sanitize_undefined)) uint16_t __pci_config_read_word(uint8_t bus, uint8_t slot,
                                                                       uint8_t func, uint8_t offset)
{
    union {
        uint8_t bytes[4];
        uint32_t val;
    } data;
    data.val = __pci_config_read_dword(bus, slot, func, offset);
    return data.bytes[(offset & 0x3)] | (data.bytes[(offset & 3) + 1] << 8);
}

void __pci_write_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t data)
{
    uint32_t address;
    uint32_t lbus = (uint32_t) bus;
    uint32_t lslot = (uint32_t) slot;
    uint32_t lfunc = (uint32_t) func;

    address = (uint32_t) ((lbus << 16) | (lslot << 11) | (lfunc << 8) | (offset & 0xfc) |
                          ((uint32_t) 0x80000000));

    scoped_lock g{pci_lock};
    /* write out the address */
    outl(CONFIG_ADDRESS, address);
    /* write out the data */
    outl(CONFIG_DATA, data);
}

// TODO: Is this valid?
void __pci_write_word_aligned(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset,
                              uint16_t data)
{
    uint32_t address;
    uint32_t lbus = (uint32_t) bus;
    uint32_t lslot = (uint32_t) slot;
    uint32_t lfunc = (uint32_t) func;

    address = (uint32_t) ((lbus << 16) | (lslot << 11) | (lfunc << 8) | (offset & 0xfc) |
                          ((uint32_t) 0x80000000));

    scoped_lock g{pci_lock};
    /* write out the address */
    outl(CONFIG_ADDRESS, address);
    /* read in the data */
    outw(CONFIG_DATA, data);
}

void __pci_write_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint16_t data)
{
    uint8_t aligned_offset = offset & -4;

    if (aligned_offset == offset)
    {
        /* NOTE: Check pcie.c's __pcie_config_write_word
         * commentary on why this is needed
         */
        __pci_write_word_aligned(bus, slot, func, offset, data);
        return;
    }

    uint8_t bshift = offset - aligned_offset;
    uint32_t byte_mask = 0xffff << (bshift * 8);
    uint32_t dword = __pci_config_read_dword(bus, slot, func, aligned_offset);
    dword = (dword & ~byte_mask) | (data << (bshift * 8));
    __pci_write_dword(bus, slot, func, aligned_offset, dword);
}

void __pci_write_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint8_t data)
{
    uint8_t aligned_offset = offset & -4;
    uint8_t byte_shift = offset - aligned_offset;
    uint32_t byte_mask = 0xff << (byte_shift * 8);
    uint32_t dword = __pci_config_read_dword(bus, slot, func, aligned_offset);
    dword = (dword & ~byte_mask) | (data << (byte_shift * 8));
    __pci_write_dword(bus, slot, func, aligned_offset, dword);
}

uint8_t __pci_read_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset)
{
    uint8_t aligned_offset = offset & -4;
    uint8_t byte_shift = offset - aligned_offset;
    uint32_t dword = __pci_config_read_dword(bus, slot, func, aligned_offset);

    return ((dword >> (byte_shift * 8)) & 0xff);
}

class legacy_acessor final : public config_accessor
{
public:
    uint64_t read(const pci::device_address& addr, uint16_t off, size_t size,
                  const pcie_allocation* alloc) override
    {
        if (alloc != nullptr || addr.segment) [[unlikely]]
        {
            panic("pci: BUG: Tried to access an ECAM/separate segment with legacy PCI");
        }

        uint64_t val = 0;
        switch (size)
        {
        case sizeof(uint16_t):
            val = __pci_config_read_word(addr.bus, addr.device, addr.function, off);
            break;
        case sizeof(uint32_t):
            val = __pci_config_read_dword(addr.bus, addr.device, addr.function, off);
            break;
        case sizeof(uint64_t):
            val = __pci_config_read_dword(addr.bus, addr.device, addr.function, off);
            break;
        case sizeof(uint8_t):
            val = __pci_read_byte(addr.bus, addr.device, addr.function, off);
            break;
        default:
            __builtin_unreachable();
        }

        return val;
    }

    void write(const pci::device_address& addr, uint64_t value, uint16_t off, size_t size,
               const pcie_allocation* alloc) override
    {
        if (alloc != nullptr || addr.segment) [[unlikely]]
        {
            panic("pci: BUG: Tried to access an ECAM/separate segment with legacy PCI");
        }

        switch (size)
        {
        case sizeof(uint8_t):
            __pci_write_byte(addr.bus, addr.device, addr.function, off, (uint8_t) value);
            break;
        case sizeof(uint16_t):
            __pci_write_word(addr.bus, addr.device, addr.function, off, (uint16_t) value);
            break;
        case sizeof(uint32_t):
            __pci_write_dword(addr.bus, addr.device, addr.function, off, (uint32_t) value);
            break;
        case sizeof(uint64_t):
            __pci_write_qword(addr.bus, addr.device, addr.function, off, value);
            break;
        default:
            __builtin_unreachable();
        }
    }
};

class legacy_acessor legacy_accessor;

__init void set_legacy_accessor()
{
    pci::set_accessor(&legacy_accessor);
}

} // namespace pci
