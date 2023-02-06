/*
 * Copyright (c) 2021 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include "include/pci_bus.h"

#include <string.h>

#include <onyx/log.h>
#include <onyx/panic.h>

#include <pci/pci.h>

#include "include/pci_root.h"

#include <onyx/memory.hpp>

namespace pci
{

#define PCI_BRIDGE_BASE_EXTENDED 1
#define PCI_BRIDGE_BASE_BITS     0x3
bool pci_device::bridge_supports_32bit_io()
{
    return (read(PCI_REGISTER_IO_BASE, sizeof(u16)) & PCI_BRIDGE_BASE_BITS) ==
           PCI_BRIDGE_BASE_EXTENDED;
}

bool pci_device::bridge_supports_64bit_prefetch()
{
    return (read(PCI_REGISTER_PREF_MEMORY_BASE, sizeof(u32)) & PCI_BRIDGE_BASE_BITS) ==
           PCI_BRIDGE_BASE_EXTENDED;
}

int pci_device::bridge_set_io_window(u32 io_start, u32 io_end)
{
    /* IO base and IO limit. These need to be 4K aligned (bottom 12 bits are hardwired to
     * 0). The bottom bit specifies that the bridge supports the extended 32-bit IO port range. It
     * is also hardwired.
     */
    constexpr u32 bottom_bits_mask = (1u << 12) - 1;
    assert((io_start & bottom_bits_mask) == 0);
    assert((io_end & bottom_bits_mask) == 0);
    u16 old = read(PCI_REGISTER_IO_BASE, sizeof(u16));
    bool supports_io32 = (old & PCI_BRIDGE_BASE_BITS) == PCI_BRIDGE_BASE_EXTENDED;

    /* Check if IO32 is supported before assigning */
    if (!supports_io32 && (io_start > UINT16_MAX || io_end > UINT16_MAX))
    {
        printf("pci: attempted to assign IO window [%x, %x] to a bridge that does not support "
               "32-bit IO\n",
               io_start, io_end - 1);
        return -EIO;
    }
    write(io_start & 0xffff, PCI_REGISTER_IO_BASE, sizeof(u16));

    /* Check if this bridge implements the IO window, if not, -EIO */
    if ((u16) read(PCI_REGISTER_IO_BASE, sizeof(u16)) == old)
    {
        printf("pci: attempted to assign IO window [%x, %x] to a bridge that does not support IO\n",
               io_start, io_end - 1);
        return -EIO;
    }

    write(io_end & 0xffff, PCI_REGISTER_IO_LIMIT, sizeof(u16));

    if (supports_io32)
    {
        write(io_start >> 16, PCI_REGISTER_UPPER_IO_BASE, sizeof(u16));
        write(io_end >> 16, PCI_REGISTER_IO_LIMIT, sizeof(u16));
    }

    return 0;
}

int pci_device::bridge_set_mem_window(u32 start, u32 end)
{
    constexpr u32 bottom_bits_mask = (1u << 20) - 1;
    assert((start & bottom_bits_mask) == 0);
    assert((end & bottom_bits_mask) == 0);
    u16 old = read(PCI_REGISTER_MEMORY_BASE, sizeof(u16));

    write((start >> 16) & 0xffff, PCI_REGISTER_MEMORY_BASE, sizeof(u16));

    /* Check if this bridge implements the MMIO window, if not, -EIO */
    if ((u16) read(PCI_REGISTER_MEMORY_BASE, sizeof(u16)) == old)
    {
        printf("pci: attempted to assign MMIO window [%x, %x] to a bridge that does not support "
               "MMIO\n",
               start, end - 1);
        return -EIO;
    }

    write((end >> 16) & 0xffff, PCI_REGISTER_MEMORY_LIMIT, sizeof(u16));

    return 0;
}

int pci_device::bridge_set_pref_mem_window(u64 start, u64 end)
{
    constexpr u32 bottom_bits_mask = (1u << 20) - 1;
    assert((start & bottom_bits_mask) == 0);
    assert((end & bottom_bits_mask) == 0);
    u16 old = read(PCI_REGISTER_PREF_MEMORY_BASE, sizeof(u16));
    bool supports_pref64 = (old & PCI_BRIDGE_BASE_BITS) == PCI_BRIDGE_BASE_EXTENDED;

    /* Check if pref64 is supported before assigning */
    if (!supports_pref64 && (start > UINT32_MAX || end > UINT32_MAX))
    {
        printf("pci: attempted to assign MMIO window [%lx, %lx] > 4GB to a "
               "bridge that does not support 64-bit mem\n",
               start, end - 1);
        return -EIO;
    }
    write((start >> 16) & 0xffff, PCI_REGISTER_PREF_MEMORY_BASE, sizeof(u16));

    /* Check if this bridge implements the MMIO window, if not, -EIO */
    if ((u16) read(PCI_REGISTER_PREF_MEMORY_BASE, sizeof(u16)) == old)
    {
        printf("pci: attempted to assign prefetchable MMIO window [%lx, %lx] to a bridge that does "
               "not support prefetchable mmio\n",
               start, end - 1);
        return -EIO;
    }

    write((end >> 16) & 0xffff, PCI_REGISTER_PREF_MEMORY_LIM, sizeof(u16));

    if (supports_pref64)
    {
        write(start >> 32, PCI_REGISTER_UPPER_IO_BASE, sizeof(u32));
        write(end >> 32, PCI_REGISTER_IO_LIMIT, sizeof(u32));
    }

    return 0;
}

/**
 * @brief Add a resource to the to-be-allocated types
 *
 * @param size Size of the resource
 * @param type Type of the resource
 */
void pci_bus::add_res(u64 size, pci_resource_type type)
{
    pci_bus_resource &res = resources[type];

    /* Ok, so the logic is to place the resources in such an order that smaller resources get stuck
     * to the tail, and larger resources get stuck to the head. This makes sure that resources are
     * always properly aligned, as everything is aligned to size, and size is always a power of 2.
     * This is useful purely to calculate the needed resource windows.
     */
    printk("type %d size %lx alignment %lx -> ", type, res.size, res.required_alignment);
    res.size += size;
    res.required_alignment = cul::max(res.required_alignment, size);
    printk(" size %lx alignment %lx\n", res.size, res.required_alignment);
}
/**
 * @brief Calculate the required resources
 * to be assigned to the PCI-PCI bridge.
 *
 */
void pci_bus::calculate_needed_resources()
{
    for_every_device([this](device *dev_) -> bool {
        pci_device *dev = (pci_device *) dev_;
        dev->for_every_resource([this](dev_resource *res) -> bool {
            /* If initialized, skip. */
            if (res->start() != 0)
                return true;
            const auto flags = res->flags();
            if (flags & DEV_RESOURCE_FLAG_IO_PORT)
            {
                this->add_res(res->size(), PCI_RSRC_TYPE_IO);
            }
            else if (flags & DEV_RESOURCE_FLAG_PREFETCHABLE)
            {
                this->add_res(res->size(), PCI_RSRC_TYPE_MEM64);
            }
            else
            {
                this->add_res(res->size(), PCI_RSRC_TYPE_MEM);
            }

            return true;
        });
        return true;
    });

    for (auto &resource : resources)
    {
        if (resource.size == 0)
            continue;
        const u64 required_alignment = resource.type == PCI_RSRC_TYPE_IO ? 0x1000 : 0x100000;
        resource.required_alignment =
            cul::align_up2(resource.required_alignment, required_alignment);
        resource.size = cul::align_up2(resource.size, required_alignment);
        printk("pci-bus %04x:%02x: needs window of alignment %lx size %lx\n",
               parent_root->get_segment(), nbus, resource.required_alignment, resource.size);
    }
}

/**
 * @brief Initialize the not-initialized bridge
 *
 */
void pci_device::init_bridge()
{
    auto parent_bus = get_pci_bus();
    /* We don't have a secondary bus, so allocate and set one */
    const u8 nbus = parent_bus->get_parent_root()->allocate_bus_nr();
    write(address.bus, PCI_REGISTER_PRIMARY_BUS, sizeof(u8));
    write(nbus, PCI_REGISTER_SECONDARY_BUS, sizeof(u8));
    write(0xff, PCI_REGISTER_SUBORDINATE_BUS, sizeof(u8));

    /* Disable all kinds of IO over the bridge, explicitly
       Note that these ranges are all disabled if limit is smaller
       than base.
    */

    bridge_set_io_window(0x2000, 0x1000);
    bridge_set_mem_window(0x200000, 0x100000);
    bridge_set_pref_mem_window(0x300000, 0x200000);
}

template <typename RandomIt>
void sort(RandomIt first, RandomIt last)
{
    using Type = typename cul::remove_reference<decltype(*RandomIt{})>::type;
    auto compare = [](const void *lhs_, const void *rhs_, void *ctx) -> int {
        const Type &lhs = *(Type *) lhs_;
        const Type &rhs = *(Type *) rhs_;

        if (lhs < rhs)
            return -1;
        else if (lhs > rhs)
            return 1;
        else
            return 0;
    };

    qsort_r(first, last - first, sizeof(Type), compare, nullptr);
}

expected<pci_root_resource, int> pci_root::carve_resource(u64 alignment, u64 size,
                                                          pci_resource_type type)
{
    unsigned int wanted_flags = 0;
    switch (type)
    {
        case PCI_RSRC_TYPE_IO:
            wanted_flags = PCI_ROOT_RSRC_IO;
            break;
        case PCI_RSRC_TYPE_MEM:
            wanted_flags = PCI_ROOT_RSRC_MEM;
            break;
        case PCI_RSRC_TYPE_MEM64:
            wanted_flags = PCI_ROOT_RSRC_MEM64;
            break;
        default:
            UNREACHABLE();
    }

retry:
    for (auto &region : host_bridge_rsrc)
    {
        if (region.flags != wanted_flags)
            continue;
        u64 misalign = region.pci_start & (alignment - 1);

        printk("pci: Trying to fit alignment %lx size %lx on [%lx, %lx]\n", alignment, size,
               region.pci_start, region.pci_start + region.size - 1);
        /* Check if we have enough size */
        if (region.size < size + misalign)
            continue;

        const u64 start = cul::align_up2(region.pci_start, alignment);
        const u64 cpu_start = cul::align_up2(region.pci_start, alignment);
        const u64 leftover = region.size - (size + misalign);

        assert((start & (alignment - 1)) == 0);
        assert((cpu_start & (alignment - 1)) == 0);

        if (misalign)
        {
            // We have a first half to reinsert into the list
            if (!host_bridge_rsrc.push_back(
                    pci_root_resource{region.pci_start, region.cpu_start, misalign, region.flags}))
                return unexpected<int>{-ENOMEM};
        }

        region.pci_start = start + size;
        region.cpu_start = cpu_start + size;
        region.size = leftover;

        printk("pci: assigning [%lx, %lx]\n", start, start + size - 1);

        return pci_root_resource{start, cpu_start, size, region.flags};
    }

    if (wanted_flags == PCI_ROOT_RSRC_MEM64)
    {
        // If we tried mem64, try mem32
        wanted_flags = PCI_ROOT_RSRC_MEM;
        goto retry;
    }

    return unexpected<int>{-EIO};
}

struct pci_res_req
{
    u64 size;
    u64 alignment;
    pci_resource_type type;
    pci_device *dev;
    dev_resource *res; // Optional
    bool operator<(const pci_res_req &rhs) const
    {
        return size < rhs.size;
    }

    bool operator>(const pci_res_req &rhs) const
    {
        return size > rhs.size;
    }
};

/**
 * @brief Assign resources to devices and bridges
 *
 */
void pci_root::assign_resources()
{
    int st = 0;
    cul::vector<pci_res_req> requests;

    for_every_device([&](device *dev_) -> bool {
        pci_device *dev = (pci_device *) dev_;
        const bool is_bridge = (dev->header_type() & PCI_TYPE_MASK) == PCI_TYPE_BRIDGE;
        dev->for_every_resource([&](dev_resource *res) -> bool {
            if (res->start() != 0)
                return true; // Already assigned

            pci_resource_type type = PCI_RSRC_TYPE_MAX;

            const auto flags = res->flags();
            if (flags & DEV_RESOURCE_FLAG_IO_PORT)
            {
                type = PCI_RSRC_TYPE_IO;
            }
            else if (flags & DEV_RESOURCE_FLAG_PREFETCHABLE)
            {
                type = PCI_RSRC_TYPE_MEM64;
            }
            else if (flags & DEV_RESOURCE_FLAG_MEM)
            {
                type = PCI_RSRC_TYPE_MEM;
            }

            assert(type != PCI_RSRC_TYPE_MAX);

            pci_res_req req;
            req.dev = dev;
            req.res = res;
            req.size = res->size();
            req.alignment = res->size();
            req.type = type;

            if (!requests.push_back(cul::move(req)))
            {
                st = -ENOMEM;
                return false;
            }

            return true;
        });

        if (is_bridge)
        {
            u8 nbus = (u8) dev->read(PCI_REGISTER_SECONDARY_BUS, sizeof(u8));
            auto bus = find_child_bus_unlocked(nbus);

            assert(bus != nullptr);

            auto insert_func = [dev, &requests](const pci_bus_resource &res) -> bool {
                pci_res_req req;
                req.alignment = res.required_alignment;
                req.size = res.size;
                req.res = nullptr;
                req.dev = dev;
                req.type = res.type;

                return requests.push_back(cul::move(req));
            };

            if (!bus->resources_to_res_req(insert_func))
            {
                st = -ENOMEM;
                return false;
            }
        }

        return st == 0;
    });

    if (st != 0)
        panic("pci: Failed to assign PCI resources: %d\n", st);

    // XXX Is sorting here a good idea? Maybe?
    sort(requests.begin(), requests.end());

    /* Algorithm: Go through the ranges in descending size and attempt to allocate. If needed to
     * split, split.
     */
    for (auto it = requests.end() - 1; it >= requests.begin(); it--)
    {
        const auto &req = *it;
        auto ex = carve_resource(req.alignment, req.size, req.type);
        auto res = ex.unwrap();
        const auto dev = req.dev;

        if (req.res)
        {
            auto resource = req.res;
            // Device resource, assign
            dev->assign_bar(resource->bus_index(), res.pci_start);
            resource->set_limits(res.cpu_start, res.cpu_start + res.size);
            // TODO: Remove this debug enable
            dev->enable_device();
        }
        else
        {
            if (req.type == PCI_RSRC_TYPE_MEM64)
            {
                dev->bridge_set_pref_mem_window(res.pci_start, res.pci_start + res.size);
            }
            else if (req.type == PCI_RSRC_TYPE_MEM)
            {
                dev->bridge_set_mem_window(static_cast<u32>(res.pci_start),
                                           static_cast<u32>(res.pci_start + res.size));
            }
            else
            {
                dev->bridge_set_io_window(static_cast<u32>(res.pci_start),
                                          static_cast<u32>(res.pci_start + res.size));
            }
        }
    }
}

/**
 * @brief Finish the bridge initialization
 *
 */
void pci_device::finish_bridge_init()
{
    write(get_pci_bus()->get_parent_root()->last_bus_nr(), PCI_REGISTER_SUBORDINATE_BUS,
          sizeof(u8));
}

pci_device *pci_bus::enumerate_device(const device_address &addr, pcie_allocation *alloc)
{
    // printk("Device at %04x:%02x:%02x.%02x\n", addr.segment, addr.bus, addr.device,
    // addr.function);

    /* Set up the pci device's name */
    char name_buf[50] = {};
    snprintf(name_buf, 50, "%04x:%02x:%02x.%02x", addr.segment, addr.bus, addr.device,
             addr.function);

    auto vendor = (uint16_t) read_config(addr, PCI_REGISTER_VENDOR_ID, sizeof(uint16_t));
    auto device_id = (uint16_t) read_config(addr, PCI_REGISTER_DEVICE_ID, sizeof(uint16_t));
    auto dev = make_unique<pci_device>(strdup(name_buf), this, nullptr, device_id, vendor, addr);
    if (!dev)
        panic("Out of memory allocating pci device");

    dev->set_alloc(alloc);

    dev->init();

    auto raw_dev = dev.get();

    bus_add_device(this, dev.release());

    if ((raw_dev->header_type() & PCI_TYPE_MASK) == PCI_TYPE_BRIDGE)
    {
        auto nbus = (uint8_t) raw_dev->read(PCI_REGISTER_SECONDARY_BUS, sizeof(uint8_t));
        bool finish_bridge_init = false;

        if (nbus == 0)
        {
            // If the secondary bus is 0, this bridge is uninitialized, so do it.
            // Then, re-read nbus
            raw_dev->init_bridge();
            nbus = (uint8_t) raw_dev->read(PCI_REGISTER_SECONDARY_BUS, sizeof(uint8_t));
            finish_bridge_init = true;
        }

        // printk("PCI-to-PCI bridge at nbus %x!\n", nbus);
        auto bus = new pci_bus{nbus, this, this->parent_root};
        if (!bus)
            panic("Out of memory allocating pci bus");

        bus->discover();

        if (finish_bridge_init)
            raw_dev->finish_bridge_init();

        bus->calculate_needed_resources();

        if (this->nbus != 0)
        {
            // If we're already under a bridge, sum this bridge's resources with our own.
            // We need to do this since this bridge's resources count like a device and need
            // to be under our own.
            for (int i = 0; i < PCI_RSRC_TYPE_MAX; i++)
            {
                const auto &res = bus->resources[i];
                auto &our_own = resources[i];
                if (res.size == 0)
                    continue;
                // TODO: Make sure that this transformation is correct.
                auto size = res.size;
                if (our_own.required_alignment)
                    size = cul::align_up2(size, our_own.required_alignment);
                our_own.size += size;
                our_own.required_alignment =
                    cul::max(our_own.required_alignment, res.required_alignment);
                printk("res %u size %lx alignment %lx\n", i, our_own.size,
                       our_own.required_alignment);
            }
        }

        add_bus(bus);

        pci::add_bus(bus);
    }

    return raw_dev;
}

void pci_bus::discover()
{
    device_address addr;
    addr.segment = parent_root->get_segment();
    addr.bus = nbus;
    addr.function = 0;
    addr.device = 0;
    auto alloc = get_alloc();

    for (unsigned int dev = 0; dev < PCI_NR_DEV; dev++)
    {
        addr.device = dev;
        addr.function = 0;
        // Probe it by reading the vendor ID - if there's no device present
        // there will be an abort generated by the PCI controller and we get an
        // all-ones value

        uint16_t vendor_id = (uint16_t) read_config(addr, PCI_REGISTER_VENDOR_ID, sizeof(uint16_t));

        if (vendor_id == 0xffff)
            continue;

        auto device = enumerate_device(addr, alloc);

        auto a = addr;

        auto header = (uint16_t) device->read(PCI_REGISTER_HEADER, sizeof(uint16_t));

        if (header & PCI_HEADER_MULTIFUNCTION)
        {
            for (int i = 1; i < 8; i++)
            {
                a.function = i;

                if ((uint16_t) read_config(a, PCI_REGISTER_VENDOR_ID, sizeof(uint16_t)) == 0xffff)
                    continue;

                enumerate_device(a, alloc);
            }
        }
    }
}

#ifdef CONFIG_ACPI

acpi_status pci_bus::route_bus_irqs(acpi_handle bus_object)
{
    acpi_buffer buf;
    buf.length = ACPI_ALLOCATE_BUFFER;

    // The gist of this is that we need to get an irq routing table for the root complex, and
    // not so much for the other buses, which may or may not have _PRT methods.
    if (auto st = acpi_get_irq_routing_table(bus_object, &buf); ACPI_FAILURE(st))
    {
        return st;
    }

    // This is all documented in ACPI spec 6.13 _PRT

    acpi_pci_routing_table *it = (acpi_pci_routing_table *) buf.pointer;
    for (; it->length != 0; it = (acpi_pci_routing_table *) ACPI_NEXT_RESOURCE(it))
    {
        // The format for Address is the same as in _ADR
        // Bits [0...16] -> Function
        // Bits [16...32] -> Device
        // It's also specified in 6.13 that Address' function field MUST be 0xffff,
        // which means all functions under $device, so we can safely ignore it and filter
        // for functions with address {$segment, $bus, $device, any}
        uint8_t devnum = it->address >> 16;

        uint32_t pin = it->pin;
        uint32_t gsi = -1;
        bool level = true;
        bool active_high = false;

        // If the first byte of the source is 0, the GSI is SourceIndex
        if (it->source[0] == 0)
        {
            gsi = it->source_index;
        }
        else
        {
            // Else, Source contains the Path of the object we need to evaluate
            // with _CRS in order to get IRQ configuration for the pin.
            acpi_handle link_obj;
            acpi_status st = acpi_get_handle(bus_object, it->source, &link_obj);

            if (ACPI_FAILURE(st))
            {
                ERROR("acpi", "Error while calling AcpiGetHandle: %x\n", st);
                return st;
            }

            acpi_buffer rbuf;
            rbuf.length = ACPI_ALLOCATE_BUFFER;
            rbuf.pointer = nullptr;

            st = acpi_get_current_resources(link_obj, &rbuf);
            if (ACPI_FAILURE(st))
            {
                ERROR("acpi", "Error while calling AcpiGetCurrentResources: %x\n", st);
                return st;
            }

            for (acpi_resource *res = (acpi_resource *) rbuf.pointer;
                 res->type != ACPI_RESOURCE_TYPE_END_TAG; res = ACPI_NEXT_RESOURCE(res))
            {
                if (res->type == ACPI_RESOURCE_TYPE_IRQ)
                {
                    level = res->data.irq.polarity == 0;
                    active_high = res->data.irq.triggering == 0;
                    gsi = res->data.irq.interrupts[it->source_index];
                    break;
                }
                else if (res->type == ACPI_RESOURCE_TYPE_EXTENDED_IRQ)
                {
                    level = res->data.extended_irq.polarity == 0;
                    active_high = res->data.extended_irq.triggering == 0;
                    gsi = res->data.extended_irq.interrupts[it->source_index];
                    break;
                }
            }

            free(rbuf.pointer);
        }

        // Find every device that matches the address mentioned above, and set
        // the pin_to_gsi information.
        // TODO: This is weird and can be done without keeping information in
        // pci_device
        for_every_device([&](device *dev_) -> bool {
            auto dev = (pci_device *) dev_;

            // Skip this device if it's not our device
            if (dev->addr().device != devnum)
                return true;

            auto pin_to_gsi = dev->get_pin_to_gsi();

            pin_to_gsi[pin].active_high = active_high;
            pin_to_gsi[pin].gsi = gsi;
            pin_to_gsi[pin].level = level;

            auto addr = dev->addr();

            printf("acpi: %04x:%02x:%02x.%02x: pin INT%c ==> GSI %u\n", addr.segment, addr.bus,
                   addr.device, addr.function, 'A' + pin, gsi);

            return true;
        });
    }

    return AE_OK;
}
#endif

/**
 * @brief Allocate a bus number for a PCI-PCI bridge
 *
 * @return Bus number
 */
u8 pci_root::allocate_bus_nr()
{
    printf("pci: allocating bus %u\n", next_bus_allocation_);
    return next_bus_allocation_++;
}

/**
 * @brief Retrieve the last bus number assigned
 *
 * @return Last bus number assigned
 */
u8 pci_root::last_bus_nr() const
{
    return next_bus_allocation_ - 1;
}

/**
 * @brief Add a resource to this root's host bridge
 *
 * @param resource PCI resource to add
 * @return 0 on success, negative error codes
 */
int pci_root::add_resource(pci_root_resource &&resource)
{
    if (!host_bridge_rsrc.push_back(cul::move(resource)))
        return -ENOMEM;
    return 0;
}

} // namespace pci
