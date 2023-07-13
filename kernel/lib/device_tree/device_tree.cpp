/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>

#include <onyx/bus_type.h>
#include <onyx/device_tree.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/serial.h>

void set_initrd_address(void *initrd_address, size_t length);

namespace device_tree
{

void *fdt_ = nullptr;

#define DEVICE_TREE_MAX_DEPTH 32

int nr_memory_ranges = 0;
size_t memory_size = 0;
unsigned long maxpfn = 0;

/**
 * @brief Process any possible memory reservations in the device tree
 *
 */
void process_reservations()
{
    int nr = fdt_num_mem_rsv(fdt_);

    for (int i = 0; i < nr; i++)
    {
        uint64_t address, size;
        if (int err = fdt_get_mem_rsv(fdt_, i, &address, &size); err < 0)
        {
            panic("device_tree: Error getting memory reservation: %s\n", fdt_strerror(err));
        }

        printf("device_tree: Memory reservation [%016lx, %016lx]\n", address, address + size - 1);

        bootmem_reserve(address, size);
    }

    printf("device_tree: Added %d memory reservations\n", nr);
}

// Taken from fdt_addresses.c since it's useful to us.
// fdt_address_cells and size_cells is not useful since it may break compatibility with
// older/broken device trees
int fdt_get_cells(const void *fdt, int nodeoffset, const char *name)
{
    const fdt32_t *c;
    uint32_t val;
    int len;

    c = (const fdt32_t *) fdt_getprop(fdt, nodeoffset, name, &len);
    if (!c)
        return len;

    if (len != sizeof(*c))
        return -FDT_ERR_BADNCELLS;

    val = fdt32_to_cpu(*c);
    if (val > FDT_MAX_NCELLS)
        return -FDT_ERR_BADNCELLS;

    return (int) val;
}

/**
 * @brief Retrieve a value from a reg field
 *
 */
uint64_t read_reg(const void *reg, int reg_offset, int cell_size)
{
    auto reg32 = (const uint32_t *) ((char *) reg + (reg_offset * sizeof(uint32_t)));
    auto reg64 = (const uint64_t *) ((char *) reg + (reg_offset * sizeof(uint32_t)));

    switch (cell_size)
    {
        case 1: {
            uint32_t ret;
            memcpy(&ret, reg32, sizeof(uint32_t));
            return fdt32_to_cpu(ret);
        }
        case 2: {
            uint64_t ret;
            memcpy(&ret, reg64, sizeof(uint64_t));
            return fdt64_to_cpu(ret);
        }
        default:
            panic("Bogus cell size");
    }
}

/**
 * @brief Gets a property of the node from the device tree
 *
 * @param name Name of the property
 * @param buf Pointer to a buffer
 * @param length Size of the buffer (needs to be the same as the length of the property)
 * @return 0 on success, negative error codes
 */
int node::get_property(const char *name, void *buf, size_t length)
{
    const void *c;
    int len;

    c = (const void *) fdt_getprop(fdt_, offset, name, &len);
    if (!c)
        return len;

    if (len != (int) length)
        return -FDT_ERR_BADLAYOUT;
    memcpy(buf, c, len);

    return 0;
}

/**
 * @brief Enumerate the device node's resources
 *
 */
void node::enumerate_resources()
{
    const int addr_cells = this->address_cells;
    const int size_cells = this->size_cells;
    int reg_len;
    const void *reg;
    if (reg = fdt_getprop(fdt_, offset, "reg", &reg_len); !reg)
    {
        // No resources
        return;
    }

    int nr_ranges = reg_len / ((addr_cells + size_cells) * sizeof(uint32_t));
    unsigned int reg_offset = 0;
    for (int i = 0; i < nr_ranges; i++)
    {
        uint64_t start, size;
        start = read_reg(reg, reg_offset, addr_cells);
        size = read_reg(reg, reg_offset + addr_cells, size_cells);
#ifdef DEVICE_TREE_DEBUG_ENUMERATE_RESOURCES
        printk("resource %lx %lx size cells %u address cells %u\n", start, size, size_cells,
               addr_cells);
#endif
        // TODO: How to autodetect if the region in reg is MMIO, IO ports (since you *can* have
        // device trees in x86)? Is it even possible?

        dev_resource *res = new dev_resource{start, start + size - 1, DEV_RESOURCE_FLAG_MEM};

        if (!res)
            panic("Could not allocate a device resource descriptor");

        // TODO: Map resources onto parent ranges
        // It turns out that device trees aren't really simple and nodes can map child address
        // spaces into other areas of the address space, and then it keeps going all the way up to
        // the root node, where you're guaranteed to deal with CPU physical addresses(since there's
        // no one above you that can map you somewhere)
        // See 2.3.8 of the device tree spec 0.4rc1 for more info
        add_resource(res);

        reg_offset += addr_cells + size_cells;
    }

    int irqs_len;
    // TODO: interrupt-cells from interrupt-parent, interrupts-extended
    const fdt32_t *irqs = (const fdt32_t *) get_property("interrupts", &irqs_len);

    if (irqs)
    {
        for (int i = 0; i < irqs_len / 4; i++)
        {
            const auto irq = fdt32_to_cpu(irqs[i]);
            dev_resource *res = new dev_resource{irq, 1, DEV_RESOURCE_FLAG_IRQ};
            if (!res)
                panic("Could not allocate a device resource descriptor");

            add_resource(res);
        }
    }
}

/**
 * @brief Handle memory@ nodes in the device tree
 *
 */
void handle_memory_node(int offset, int addr_cells, int size_cells)
{
    int reg_len;
    const void *reg;
    if (reg = fdt_getprop(fdt_, offset, "reg", &reg_len); !reg)
    {
        panic("device_tree: error parsing memory node: %s\n", fdt_strerror(reg_len));
    }

    int nr_ranges = reg_len / ((addr_cells + size_cells) * sizeof(uint32_t));
    unsigned int reg_offset = 0;

    for (int i = 0; i < nr_ranges; i++)
    {
        uint64_t start, size;
        start = read_reg(reg, reg_offset, addr_cells);
        size = read_reg(reg, reg_offset + addr_cells, size_cells);

        bootmem_add_range(start, size);
        memory_size += size;

        maxpfn = cul::max((start + size) >> PAGE_SHIFT, maxpfn);
        base_pfn = cul::min(start >> PAGE_SHIFT, base_pfn);

        reg_offset += addr_cells + size_cells;
    }
}

void figure_out_initrd_from_chosen(int offset)
{
    int len;
    uint64_t start, end;

    const void *startp = (const fdt64_t *) fdt_getprop(fdt_, offset, "linux,initrd-start", &len);

    switch (len)
    {
        case 4:
            start = fdt32_to_cpu(*(const fdt32_t *) startp);
            break;
        case 8:
            start = fdt64_to_cpu(*(const fdt64_t *) startp);
            break;
        default:
            // handles no linux,initrd-{start, end} errors + weird lengths
            return;
    }

    const void *endp = (const fdt64_t *) fdt_getprop(fdt_, offset, "linux,initrd-end", &len);

    switch (len)
    {
        case 4:
            end = fdt32_to_cpu(*(const fdt32_t *) endp);
            break;
        case 8:
            end = fdt64_to_cpu(*(const fdt64_t *) endp);
            break;
        default:
            // handles no linux,initrd-{start, end} errors + weird lengths
            return;
    }

    bootmem_reserve(start, end - start);

    set_initrd_address((void *) start, end - start);
}
/**
 * @brief Walk the device tree and look for interesting things
 *
 */
void early_walk()
{
    int address_cell_stack[DEVICE_TREE_MAX_DEPTH];
    int size_cell_stack[DEVICE_TREE_MAX_DEPTH];

    // We need to take special care with #address-cells and #size-cells.
    // The default is 1 for both, but each node inherits the parent's #-cells.
    // Because of that, we have to keep a stack of address and size cells.
    // Because this is early boot code, we don't have access to dynamic memory,
    // so we choose a relatively safe MAX_DEPTH of 32. Hopefully, no crazy device trees come our
    // way.

    // 2 is the default for #address-cells, 1 is the default for #size-cells
    address_cell_stack[0] = fdt_address_cells(fdt_, 0);
    size_cell_stack[0] = fdt_size_cells(fdt_, 0);

    int depth = 0;
    int offset = 0;

    while (true)
    {
        offset = fdt_next_node(fdt_, offset, &depth);

        if (offset < 0 || depth < 0)
            break;

        if (depth >= DEVICE_TREE_MAX_DEPTH)
        {
            printf("device_tree: error: Depth %d exceeds max depth\n", depth);
            return;
        }

        if (depth > 0)
        {
            // Use the parent's cell sizes
            address_cell_stack[depth] = address_cell_stack[depth - 1];
            size_cell_stack[depth] = size_cell_stack[depth - 1];
        }

        // Try to fetch #address-cells and #size-cells

        if (int cells = fdt_get_cells(fdt_, offset, "#address-cells"); cells > 0)
        {
            address_cell_stack[depth] = cells;
        }

        if (int cells = fdt_get_cells(fdt_, offset, "#size-cells"); cells > 0)
        {
            size_cell_stack[depth] = cells;
        }

        const char *name = fdt_get_name(fdt_, offset, NULL);
        if (!name)
            continue;

        if (!strncmp(name, "memory@", strlen("memory@")))
        {
            handle_memory_node(offset, address_cell_stack[depth], size_cell_stack[depth]);
        }
        else if (!strncmp(name, "chosen", strlen("chosen")))
        {
            figure_out_initrd_from_chosen(offset);
        }
    }
}

/**
 * @brief Initialise the device tree subsystem of the kernel
 *
 * @param fdt Pointer to the flattened device tree
 */
void init(void *fdt)
{
    fdt_ = PHYS_TO_VIRT(fdt);

    if (int error = fdt_check_header(fdt_); error < 0)
    {
        printf("fdt: Bad header: %s\n", fdt_strerror(error));
        return;
    }

    // Reserve the FDT in case the device tree hasn't done that
    bootmem_reserve((unsigned long) fdt, fdt_totalsize(fdt_));

    process_reservations();

    early_walk();

    page_init(memory_size, maxpfn);
}

node *root_node;
cul::vector<node *> phandle_map;

/**
 * @brief Map a phandle ID to a node
 *
 * @param phandle phandle ID
 * @return Node that it maps to, or nullptr if not found.
 */
node *map_phandle(uint32_t phandle)
{
    if (phandle >= phandle_map.size())
        return nullptr;
    return phandle_map[phandle];
}

/**
 * @brief Get the root dt node
 *
 * @return Pointer to the root node
 */
node *get_root()
{
    return root_node;
}

bus_type *dt_bus;
list_head device_list = LIST_HEAD_INIT(device_list);

/**
 * @brief Enumerate the device tree
 *        Note: Requires dynamic memory allocation
 */
void enumerate()
{
    dt_bus = new bus_type{"device-tree"};
    if (!dt_bus)
        panic("Failed to allocate bus type structure for dt");

    root_node = new node{cul::string(""), 0, 0};
    if (!root_node)
        panic("Failed to allocate a device tree node");

    uint32_t max_phandle;
    fdt_find_max_phandle(fdt_, &max_phandle);
    if (!phandle_map.resize(max_phandle + 1))
        panic("Failed to allocate the phandle list");

    /* Zero-init the phandle list */
    for (auto &p : phandle_map)
        p = nullptr;

    int address_cell_stack[DEVICE_TREE_MAX_DEPTH];
    int size_cell_stack[DEVICE_TREE_MAX_DEPTH];
    node *parents[DEVICE_TREE_MAX_DEPTH];

    // 2 is the default for #address-cells, 1 is the default for #size-cells
    address_cell_stack[0] = fdt_address_cells(fdt_, 0);
    size_cell_stack[0] = fdt_size_cells(fdt_, 0);

    int depth = 0;
    int offset = 0;
    parents[0] = root_node;

    while (true)
    {
        offset = fdt_next_node(fdt_, offset, &depth);

        if (offset < 0 || depth < 0)
            break;

        if (depth >= DEVICE_TREE_MAX_DEPTH)
        {
            printf("device_tree: error: Depth %d exceeds max depth\n", depth);
            return;
        }

        u32 interrupt_parent;
        int len;

        if (const void *ptr = fdt_getprop(fdt_, offset, "interrupt-parent", &len); ptr)
        {
            const fdt32_t *p = (const fdt32_t *) ptr;
            interrupt_parent = fdt32_to_cpu(*p);
        }
        else
        {
            // If we have no property there, inherit our parent's
            if (depth > 0)
                interrupt_parent = parents[depth - 1]->interrupt_parent;
            else
            {
                // We have no parent, so set it to -1 just so it blows up if we ever try to use it
                interrupt_parent = -1;
            }
        }

        if (depth > 0)
        {
            // Use the parent's cell sizes
            address_cell_stack[depth] = address_cell_stack[depth - 1];
            size_cell_stack[depth] = size_cell_stack[depth - 1];
        }

        // Try to fetch #address-cells and #size-cells

        if (int cells = fdt_get_cells(fdt_, offset, "#address-cells"); cells > 0)
        {
            address_cell_stack[depth] = cells;
        }

        if (int cells = fdt_get_cells(fdt_, offset, "#size-cells"); cells > 0)
        {
            size_cell_stack[depth] = cells;
        }

        const char *name_ = fdt_get_name(fdt_, offset, NULL);
        if (!name_)
            continue;

        cul::string name{name_};
        if (!name)
            panic("Failed to allocate memory for the device tree node");

        auto dev_node = new node{cul::move(name), offset, depth, parents[depth - 1]};

        if (!dev_node)
            panic("Failed to allocate a device tree node");
        list_add_tail(&dev_node->list_node, &device_list);

        dev_node->address_cells = address_cell_stack[depth];
        dev_node->size_cells = size_cell_stack[depth];
        dev_node->interrupt_parent = interrupt_parent;
        dev_node->enumerate_resources();

        if (!parents[depth - 1]->children.push_back(dev_node))
            panic("Failed to allocate memory for the device tree");

        uint32_t phandle = fdt_get_phandle(fdt_, offset);

        if (phandle)
        {
            /* We have a phandle, register ourselves */
            if (phandle_map[phandle])
            {
                panic("We already had phandle %u registered, bad device tree?", phandle);
            }

            phandle_map[phandle] = dev_node;
        }

        parents[depth] = dev_node;
    }
}

bool dev_tree_driver_supports_device(driver *drv, node *node)
{
    int length;
    const char *compat_strings = (const char *) node->get_property("compatible", &length);
    const char *s = compat_strings;
    if (!compat_strings)
        return false;

    int i = 0;
    while (i < length)
    {
        size_t string_size = strnlen(s, length - i);
        std::string_view compat_str{s, string_size};
        s += string_size + 1;
        i += string_size + 1;

        const char **compat_string_array = (const char **) drv->devids;

        while (*compat_string_array)
        {
            const char *str = *compat_string_array++;

            if (compat_str == str)
            {
                return true;
            }
        }
    }

    return false;
}

void devtree_driver_register(struct driver *driver)
{
    list_for_every (&device_list)
    {
        auto dev = list_head_cpp<node>::self_from_list_head(l);

        if (dev_tree_driver_supports_device(driver, dev))
        {
            driver_register_device(driver, dev);
            if (driver->probe(dev) < 0)
                driver_deregister_device(driver, dev);
        }
    }
}

/**
 * @brief Register a driver with the device tree subsystem
 *
 * @param driver_
 */
void register_driver(driver *driver_)
{
    dt_bus->add_driver(driver_);
    devtree_driver_register(driver_);
}

/**
 * @brief Open a device tree node
 *
 * @param path Path of the node
 * @return Pointer to the node
 */
node *open_node(std::string_view path, node *base_node)
{
    size_t pos = 0;
    if (!base_node)
        base_node = root_node;

    if (path[0] == '/')
    {
        pos++;
        base_node = root_node;
    }

    while (pos < path.length())
    {
        auto path_elem_end = path.find('/', pos);
        if (path_elem_end == std::string_view::npos) [[unlikely]]
        {
            path_elem_end = path.length();
        }

        std::string_view v = path.substr(pos, path_elem_end - pos);
        pos += v.length() + 1;

        base_node = base_node->open_node(v);
        if (!base_node)
            return nullptr;
    }

    return base_node;
}

/**
 * @brief Gets a property of the node from the device tree
 *
 * @param name Name of the property
 * @param length Pointer to the length, or negative error codes
 * @return Pointer to property
 */
const void *node::get_property(const char *name, int *length)
{
    return fdt_getprop(fdt_, offset, name, length);
}

} // namespace device_tree
