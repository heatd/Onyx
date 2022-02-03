/*
 * Copyright (c) 2016-2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <onyx/acpi.h>
#include <onyx/bus_type.h>
#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/log.h>
#include <onyx/panic.h>
#include <onyx/timer.h>
#include <onyx/vector.h>

#include <pci/pci.h>

#include "include/config_accessor.h"
#include "include/pci_root.h"

#include <onyx/memory.hpp>

namespace pci
{

bus_type pci{"pci"};
config_accessor *accessor = nullptr;

void set_accessor(config_accessor *a)
{
    accessor = a;
}

uint64_t read_config(const device_address &addr, uint16_t off, size_t size)
{
    return accessor->read(addr, off, size, nullptr);
}

void write_config(const device_address &addr, uint64_t value, uint16_t off, size_t size)
{
    accessor->write(addr, value, off, size, nullptr);
}

uint64_t pci_device::read(uint16_t off, size_t size) const
{
    return accessor->read(address, off, size, alloc);
}

void pci_device::write(uint64_t value, uint16_t off, size_t size) const
{
    accessor->write(address, value, off, size, alloc);
}

void pci_device::find_supported_capabilities()
{
    size_t pm_off = find_capability(PCI_CAP_ID_POWER_MANAGEMENT_INTERFACE, 0);
    if (pm_off == 0)
    {
        /* We found the PM Register block! Great, now we'll cache the offset and the
         * fact that the capability exists
         */
        has_power_management = true;
        pm_cap_off = (uint8_t) pm_off;
        /* Now, grab the PMC and cache the available power states
         * The PMC is at pm_off + 2, and is 16 bits in size
         */
        uint16_t pmc = read(pm_off + 2, sizeof(uint16_t));
        /* D0 and D3 are always supported */
        supported_power_states = PCI_POWER_STATE_D0 | PCI_POWER_STATE_D3;
        if (pmc & PCI_PMC_D1_SUPPORT)
            supported_power_states |= PCI_POWER_STATE_D1;
        if (pmc & PCI_PMC_D2_SUPPORT)
            supported_power_states |= PCI_POWER_STATE_D2;
    }
}

void pci_device::init()
{
    uint32_t word = (uint32_t) read_config(address, PCI_REGISTER_REVISION_ID, sizeof(uint32_t));
    prog_if_ = (word >> 8) & 0xFF;
    sub_class_ = (word >> 16) & 0xFF;
    pci_class_ = (word >> 24) & 0xFF;

    uint16_t header = (uint16_t) read_config(address, PCI_REGISTER_HEADER, sizeof(uint16_t));

    current_power_state = PCI_POWER_STATE_D0;
    type = header & PCI_TYPE_MASK;
    /* Find supported caps and add them to dev */
    find_supported_capabilities();

    assert(device_init(this) == 0);
}

#define PCI_MAX_BAR         5
#define PCI_BAR_GET_TYPE(x) ((x >> 1) & 0x3)
#define PCI_BAR_TYPE_32     0
#define PCI_BAR_TYPE_64     0x2

#define PCI_BAR_IO_RANGE     (1 << 0)
#define PCI_BAR_PREFETCHABLE (1 << 3)

expected<pci_bar, int> pci_device::get_bar(unsigned int index)
{
    assert(index <= PCI_MAX_BAR);

    pci_bar b;

    uint16_t offset = PCI_BARx(index);

    uint32_t word = (uint32_t) read(offset, sizeof(word));
    uint32_t upper_half = 0;

    b.is_iorange = word & PCI_BAR_IO_RANGE;
    b.may_prefetch = word & PCI_BAR_PREFETCHABLE;

    bool is_64 = PCI_BAR_GET_TYPE(word) == PCI_BAR_TYPE_64;

    if (is_64)
    {
        upper_half = read(PCI_BARx((index + 1)), sizeof(uint32_t));
    }

    uint32_t mask = 0xfffffff0;
    if (b.is_iorange)
    {
        mask = 0xfffffffc;
    }

    b.address = word & mask;
    b.address |= ((uint64_t) upper_half << 32);

    /* Get the size */
    write(0xffffffff, offset, sizeof(uint32_t));

    uint32_t size = (~((read(offset, sizeof(uint32_t)) & 0xfffffff0))) + 1;
    b.size = size;

    write(word, offset, sizeof(uint32_t));

    return b;
}

void *pci_device::map_bar(unsigned int index, unsigned int caching)
{
    struct pci_bar bar;
    auto st = get_bar(index);

    if (st.has_error())
        return nullptr;
    else
    {
        bar = st.value();
    }

    if (bar.is_iorange)
    {
        printf("pci: warning: trying to map io range\n");
        return nullptr;
    }

#if 0
	printf("Mapping bar%d %lx %lx\n", index, bar.address, bar.size);
#endif

    return mmiomap((void *) bar.address, bar.size, VM_WRITE | VM_NOEXEC | caching);
}

uint16_t pci_device::get_intn() const
{
    uint8_t pin = read(PCI_REGISTER_INTN, sizeof(uint16_t)) >> 8;
    if (pin == 0xff)
        return UINT16_MAX;

    /* Make the pin a 0-based int so it fits nicely with the array */
    pin--;

    uint16_t intn = pin_to_gsi[pin].gsi;

    // TODO: Separate this or something like that
#if __x86_64__
    ioapic_set_pin(pin_to_gsi[pin].active_high, pin_to_gsi[pin].level, intn);
#endif
    return intn;
}

// TODO: We may need a lock here when hot-plugging?
cul::vector<unique_ptr<pci_root>> pci_roots;

int init_root_bus(uint16_t segment, uint8_t bus_nr, ACPI_HANDLE bus_object)
{
    if (pci_roots.size() != 0 && !pcie_is_enabled())
    {
        panic("Firmware bug: Multiple PCI root buses in firmware tables without PCIe");
    }

    auto bus = make_unique<pci_root>(segment, bus_nr);
    if (!bus)
        return -ENOMEM;

    // Get a quick pointer to the bus object, we'll stop owning after pushing
    auto bus_raw = bus.get();

    add_bus(bus_raw);

    if (!pci_roots.push_back(cul::move(bus)))
        return -ENOMEM;

    bus_raw->discover();

    bus_raw->route_irqs(bus_object);

    return 0;
}

void pci_root::route_irqs(ACPI_HANDLE bus_object)
{
    // The root complex must have a valid routing table
    if (auto st = route_bus_irqs(bus_object); ACPI_FAILURE(st))
    {
        ERROR("pci", "Error getting IRQ routing table for root complex.");
        return;
    }

    // Try to find all buses under the root complex and get their IRQ routing tables
    // since, annoyingly, each table only handles a single bus.
    ACPI_HANDLE handle = nullptr;
    while (AcpiGetNextObject(ACPI_TYPE_DEVICE, bus_object, handle, &handle) == AE_OK)
    {
        // TODO: This whole routing logic doesn't work for devices behind PCI-PCI bridges
        // Investigate.

        ACPI_DEVICE_INFO *info;
        if (AcpiGetObjectInfo(handle, &info) != AE_OK)
            continue;

        uint8_t bridge_device = (uint8_t) (info->Address >> 16);
        uint8_t bridge_func = (uint8_t) (info->Address & 0xff);

        auto dev = find_device(bridge_device, bridge_func);
        if (!dev)
        {
            ERROR("pci", "Firmware tables reference non-existent bridge %04x:%02x:%02x.%02x\n",
                  parent_root->get_segment(), nbus, bridge_device, bridge_func);
            free((void *) info);
            continue;
        }

        if ((dev->header_type() & PCI_TYPE_MASK) != PCI_TYPE_BRIDGE)
        {
            // Not a bridge, go on
            free((void *) info);
            continue;
        }

        // TODO: Keeping a reference to the pci_bus in pci_device might be a good idea?
        auto bus_nr = (uint8_t) (dev->read(PCI_REGISTER_SECONDARY_BUS, sizeof(uint8_t)));

        auto bus = find_child_bus(bus_nr);
        if (!bus)
        {
            ERROR("pci", "Child bus %x does not exist.\n", bus_nr);
            free((void *) info);
            continue;
        }

        bus->route_bus_irqs(handle);

        free((void *) info);
    }
}

pcie_allocation *pci_bus::get_alloc() const
{
    return find_alloc_for_root(parent_root->get_segment(), nbus);
}

void enumerate_buses()
{
    // Traverse the ACPI tables and look at them for guidance
    acpi::find_root_pci_buses(init_root_bus);
}

void add_bus(pci_bus *b)
{
    pci.add_bus(b);
}

void pci_init(void)
{
    pcie_get_mcfg();

    if (pcie_is_enabled())
    {
        pcie_init();
    }

    enumerate_buses();
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(pci_init);

void pci_device::set_bar(const pci_bar &bar, unsigned int index)
{
    uint32_t bar_word = (uint32_t) bar.address | bar.is_iorange | (bar.may_prefetch << 2);
    write(bar_word, PCI_BARx(index), sizeof(bar_word));
}

void pci_device::enable_busmastering()
{
    uint32_t command_register = (uint32_t) read(PCI_REGISTER_COMMAND, sizeof(uint32_t));
    write(command_register | PCI_COMMAND_BUS_MASTER, PCI_REGISTER_COMMAND, sizeof(uint32_t));
}

uint16_t pci_device::get_status() const
{
    return (uint16_t) read(PCI_REGISTER_STATUS, sizeof(uint16_t));
}

size_t pci_device::find_capability(uint8_t cap, int instance)
{
    uint16_t status = get_status();
    if (!(status & PCI_STATUS_CAP_LIST_SUPPORTED))
        return 0;

    uint8_t offset = (uint8_t) read(PCI_REGISTER_CAPABILTIES_POINTER, sizeof(uint8_t)) & ~3;

    while (offset)
    {
        uint16_t _cap = read(offset, sizeof(uint16_t));

        if ((_cap & 0xFF) == cap && instance-- == 0)
            return offset;

        offset = ((uint8_t) (_cap >> 8)) & ~3;
    }

    return 0;
}

void pci_device::disable_busmastering()
{
    uint32_t command_register = (uint32_t) read(PCI_REGISTER_COMMAND, sizeof(uint32_t));
    write(command_register & ~PCI_COMMAND_BUS_MASTER, PCI_REGISTER_COMMAND, sizeof(uint32_t));
}

void pci_device::disable_irq()
{
    uint32_t command_register = (uint32_t) read(PCI_REGISTER_COMMAND, sizeof(uint32_t));
    write(command_register | PCI_COMMAND_INTR_DISABLE, PCI_REGISTER_COMMAND, sizeof(uint32_t));
}

void pci_device::enable_irq()
{
    uint32_t command_register = (uint32_t) read(PCI_REGISTER_COMMAND, sizeof(uint32_t));
    write(command_register & ~PCI_COMMAND_INTR_DISABLE, PCI_REGISTER_COMMAND, sizeof(uint32_t));
}

struct pci_id *pci_driver_supports_device(struct driver *driver, pci_device *dev)
{
    struct pci_id *dev_table = (pci_id *) driver->devids;

    for (; dev_table->vendor_id != 0; dev_table++)
    {
        if (dev_table->vendor_id != PCI_ANY_ID)
        {
            if (dev_table->vendor_id != dev->vid())
                continue;
        }

        if (dev_table->device_id != PCI_ANY_ID)
        {
            if (dev_table->device_id != dev->did())
                continue;
        }

        if (dev_table->pci_class != PCI_ANY_ID)
        {
            if (dev_table->pci_class != dev->pci_class())
                continue;
        }

        if (dev_table->subclass != PCI_ANY_ID)
        {
            if (dev_table->subclass != dev->sub_class())
                continue;
        }

        if (dev_table->progif != PCI_ANY_ID)
        {
            if (dev_table->progif != dev->prog_if())
                continue;
        }

        return dev_table;
    }

    return nullptr;
}

void __pci_bus_register(struct driver *driver, struct bus *bus)
{
    list_for_every (&bus->device_list_head)
    {
        auto dev = list_head_cpp<pci_device>::self_from_list_head(l);
        struct pci_id *id;
#if 0
		printk("%04x:%02x:%02x:%02x -> %04x:%04x ",
			dev->addr().segment, dev->addr().bus, dev->addr().device, dev->addr().function,
			dev->did(), dev->vid());
#endif
        // Bound, skip.
        if (dev->driver_)
        {
#if 0
			printk(" bound\n");
#endif
            continue;
        }
#if 0
		printk("\n");
#endif
        if ((id = pci_driver_supports_device(driver, dev)))
        {
            dev->set_driver_data(id->driver_data);
            driver_register_device(driver, dev);
            if (driver->probe(dev) < 0)
                driver_deregister_device(driver, dev);
        }
    }
}

void register_driver(struct driver *driver)
{
    pci.add_driver(driver);

    pci.for_every_bus([&](struct bus *bus) -> bool {
        __pci_bus_register(driver, bus);
        return true;
    });
}

int pci_device::enable_device()
{
    int st = set_power_state(PCI_POWER_STATE_D0);

    if (st < 0)
    {
        /* Check if the device could actually change power states */
        if (st != -ENOSYS)
            return -1;
        /* If it failed purely because we can't change it, proceed
         * since the device is already in D0
         */
    }

    /* Enable the IO and MMIO of the device */
    uint16_t command = (uint16_t) read(PCI_REGISTER_COMMAND, sizeof(uint16_t));
    command |= PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_IOSPACE;

    write(command, PCI_REGISTER_COMMAND, sizeof(uint16_t));

    return 0;
}

#define PCI_AF_REG_LENGTH  2
#define PCI_AF_REG_AF_CAPS 3
#define PCI_AF_REG_CONTROL 4
#define PCI_AF_REG_STATUS  5

#define PCI_AF_CAP_TP  (1 << 0)
#define PCI_AF_CAP_FLR (1 << 1)

#define PCI_AF_INTIATE_FLR (1 << 0)

#define PCI_AF_STATUS_TP (1 << 0)

int pci_device::wait_for_tp(off_t cap_start)
{
    while (!(read(cap_start + PCI_AF_REG_STATUS, sizeof(uint16_t)) & PCI_AF_STATUS_TP))
        ;

    return 0;
}

int pci_device::reset_device()
{
    size_t off = find_capability(PCI_CAP_ID_AF, 0);
    if (off == 0)
        return -ENOTSUP;

    if (read(off + PCI_AF_REG_LENGTH, sizeof(uint8_t)) != 6)
    {
        ERROR("pci", "pci device at %04x:%02x:%02x:%02x has an invalid AF\n", address.segment,
              address.bus, address.device, address.function);
        return -EIO;
    }

    uint8_t caps = read(off + PCI_AF_REG_AF_CAPS, sizeof(uint8_t));

    /* Check for TP and FLR */
    if (!(caps & PCI_AF_CAP_TP) || !(caps & PCI_AF_CAP_FLR))
        return -EIO;

    write(PCI_AF_INTIATE_FLR, off + PCI_AF_REG_CONTROL, sizeof(uint8_t));

    return wait_for_tp(off);
}

} // namespace pci
