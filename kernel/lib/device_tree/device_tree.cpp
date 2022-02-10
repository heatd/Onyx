/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>

#include <onyx/device_tree.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/serial.h>

static char buffer[1000];

#define budget_printk(...)                         \
    snprintf(buffer, sizeof(buffer), __VA_ARGS__); \
    platform_serial_write(buffer, strlen(buffer))

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

        budget_printk("start %016lx\n", start);

        bootmem_add_range(start, size);
        memory_size += size;

        maxpfn = cul::max((start + size) >> PAGE_SHIFT, maxpfn);
        base_pfn = cul::min(start >> PAGE_SHIFT, base_pfn);

        reg_offset += addr_cells + size_cells;
    }
}

/**
 * @brief Walk the device tree and look for interesting things
 *
 */
void walk()
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

    walk();

    page_init(memory_size, maxpfn);
}

} // namespace device_tree
