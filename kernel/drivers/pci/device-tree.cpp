/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/device_tree.h>

#include "include/pci_bus.h"
#include "include/pci_root.h"

#ifdef CONFIG_DEVICE_TREE

static const char *pci_root_dt_ids[] = {"pci-host-ecam-generic", nullptr};

namespace pci
{

#define PCI_DATA_SPACE_CODE_SHIFT 24
#define PCI_DATA_SPACE_CODE_MASK  (0x3)
#define PCI_DATA_IO_RANGE         (1U << 0)
#define PCI_DATA_MEM32            (1U << 1)
#define PCI_DATA_MEM64            (0x3)

int enumerate_root_bus_resources(pci_root *root, device_tree::node *dev)
{
    int length;
    const u32 *ranges = (const u32 *) dev->get_property("ranges", &length);
    if (!ranges)
    {
        printf("pci-dt: device has no ranges property\n");
        return -EIO;
    }

    const u32 *end = ranges + length / 4;

    // printk("addr cells %d\n", dev->address_cells);

    u32 data;
    u64 pci_address;
    u64 cpu_address;
    u64 size;

    // XXX not done properly
    while (ranges < end)
    {
        data = fdt32_to_cpu(*ranges);
        ranges++;
        memcpy(&pci_address, ranges, sizeof(u64));
        pci_address = fdt64_to_cpu(pci_address);
        ranges += 2;
        memcpy(&cpu_address, ranges, sizeof(u64));
        cpu_address = fdt64_to_cpu(cpu_address);
        ranges += 2;
        memcpy(&size, ranges, sizeof(u64));
        size = fdt64_to_cpu(size);
        ranges += 2;

        auto type = (data >> PCI_DATA_SPACE_CODE_SHIFT) & PCI_DATA_SPACE_CODE_MASK;
        const char *str = "unknown";
        unsigned int flags = 0;

        switch (type)
        {
            case PCI_DATA_IO_RANGE:
                str = "io";
                flags = PCI_ROOT_RSRC_IO;
                break;
            case PCI_DATA_MEM32:
                str = "mem";
                flags = PCI_ROOT_RSRC_MEM;
                break;
            case PCI_DATA_MEM64:
                str = "mem64";
                flags = PCI_ROOT_RSRC_MEM64;
                break;
        }

        printk("pci-dt: range %s pci %lx cpu %lx size %lx\n", str, pci_address, cpu_address, size);

        if (flags != 0)
        {
            int st = root->add_resource(pci_root_resource{pci_address, cpu_address, size, flags});

            if (st < 0)
            {
                printf("pci-dt: error adding host bridge resource: %s\n", strerror(-st));
                return st;
            }
        }
    }

    return 0;
}

int init_root_bus(u16 segment, u8 bus_nr, device_tree::node *dev)
{
    auto bus = make_unique<pci_root>(segment, bus_nr);
    if (!bus)
        return -ENOMEM;

    auto bus_raw = bus.get();

    if (int st = enumerate_root_bus_resources(bus_raw, dev); st < 0)
        return st;

    add_bus(bus_raw);

    bus->discover();
    bus->assign_resources();
    bus.release();

    return 0;
}

static int pci_root_probe(struct device *dev_)
{
    auto dev = (device_tree::node *) dev_;

    auto ecam = dev->get_resource(DEV_RESOURCE_FLAG_MEM);
    if (!ecam)
    {
        printf("error: pci-host-ecam-generic has no ecam range\n");
        return -EIO;
    }

    u8 start_bus = 0;
    u8 end_bus = 255;

    /* If bus-range is present, use that */
    u32 bus_range[2];

    if (dev->get_property("bus-range", bus_range, sizeof(bus_range)) == 0)
    {
        start_bus = fdt32_to_cpu(bus_range[0]);
        end_bus = fdt32_to_cpu(bus_range[1]);
    }

    int st = pci::add_ecam(0, start_bus, end_bus, ecam->start());

    if (st < 0)
        return st;
    printf("pci-dt: Found ECAM@%016lx for buses [%u, %u]\n", ecam->start(), start_bus, end_bus);

    return init_root_bus(0, start_bus, dev);
}

static driver pci_root_dt = {
    .name = "pci-root-devtree",
    .devids = pci_root_dt_ids,
    .probe = pci_root_probe,
    .bus_type_node = &pci_root_dt,
};

int pci_root_dt_init()
{
    device_tree::register_driver(&pci_root_dt);
    return 0;
}

DRIVER_INIT(pci_root_dt_init);

} // namespace pci

#endif
