/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <onyx/bootmem.h>
#include <onyx/page.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/serial.h>

#define DEFAULT_NR_MEMORY_RANGES 128

struct memory_range
{
    unsigned long start;
    size_t size;
};

memory_range phys_ranges[DEFAULT_NR_MEMORY_RANGES];
unsigned int nr_phys_ranges = 0;

memory_range resv_ranges[DEFAULT_NR_MEMORY_RANGES];
unsigned int nr_resv_ranges = 0;

void for_every_phys_region(void (*callback)(unsigned long start, size_t size))
{
    for (unsigned int i = 0; i < nr_phys_ranges; i++)
        callback(phys_ranges[i].start, phys_ranges[i].size);
}

static void __bootmem_add_range(unsigned long start, size_t size)
{
    if (nr_phys_ranges == DEFAULT_NR_MEMORY_RANGES)
    {
        panic("Out of space for memory range [%016lx, %016lx]", start, start + size - 1);
    }

    // Attempt to coalesce entries. It's a major win when the memory map is highly fragmented
    // cough cough EFI. Do it backwards since it's way more likely we exit early, as most
    // boot code will add them in growing order.
    for (size_t i = nr_phys_ranges; i > 0; i--)
    {
        if (phys_ranges[i - 1].start + phys_ranges[i - 1].size == start)
        {
            phys_ranges[i - 1].size += size;
            return;
        }
    }

    phys_ranges[nr_phys_ranges++] = memory_range{start, size};
}

static void bootmem_re_reserve_memory();

void bootmem_add_range(unsigned long start, size_t size)
{
    __bootmem_add_range(start, size);

    // We need to run this because we might already have memory reservations registered
    bootmem_re_reserve_memory();
}

static void bootmem_remove_range(unsigned int index)
{
    auto tail_ranges = nr_phys_ranges - index - 1;
    memmove(&phys_ranges[index], &phys_ranges[index + 1], tail_ranges * sizeof(memory_range));
    nr_phys_ranges--;
}

static void bootmem_add_reserve(unsigned long start, size_t size)
{
    if (nr_resv_ranges == DEFAULT_NR_MEMORY_RANGES)
    {
        panic("Out of space for reserved memory range [%016lx, %016lx]", start, start + size - 1);
    }

    printf("bootmem: Added reserved memory range [%016lx, %016lx]\n", start, start + size - 1);

    resv_ranges[nr_resv_ranges++] = memory_range{start, size};
}

static void bootmem_reserve_memory_ranges(unsigned long start, size_t size)
{
    for (unsigned int i = 0; i < nr_phys_ranges; i++)
    {
        auto &range = phys_ranges[i];
        bool overlaps =
            check_for_overlap(start, start + size - 1, range.start, range.start + range.size - 1);

        if (!overlaps)
        {
            continue;
        }

        if (range.start >= start)
        {
            unsigned long offset = range.start - start;
            const auto tail_size = (size - offset) > range.size ? 0 : range.size - (size - offset);

            if (!tail_size)
            {
                // If we end up not having a tail, remove the range altogether
                bootmem_remove_range(i);
            }
            else
            {
                // Trim the start of the range
                range.size = tail_size;
                range.start = range.start + (size - offset);
            }
        }
        else if (range.start < start)
        {
            unsigned long offset = start - range.start;
            unsigned long remainder = range.size - offset;
            auto to_shave_off = size < remainder ? size : remainder;

            if (to_shave_off == range.size)
            {
                range.size -= to_shave_off;
            }
            else
            {
                unsigned long second_region_start = start + to_shave_off;
                unsigned long second_region_size = remainder - to_shave_off;

                range.size = offset;
                __bootmem_add_range(second_region_start, second_region_size);
            }
        }
    }
}

/**
 * @brief Run the reservation code on all the memory that has been registered
 *
 */
static void bootmem_re_reserve_memory()
{
    for (unsigned int i = 0; i < nr_resv_ranges; i++)
    {
        bootmem_reserve_memory_ranges(resv_ranges[i].start, resv_ranges[i].size);
    }
}

void bootmem_reserve(unsigned long start, size_t size)
{
    // Reservations align downwards on the start and upwards on the size
    size += start & (PAGE_SIZE - 1);
    start &= -PAGE_SIZE;
    size = (size_t) page_align_up((void *) size);

    bootmem_add_reserve(start, size);
    bootmem_reserve_memory_ranges(start, size);
}

void *alloc_boot_page(size_t nr_pages, long flags)
{
    size_t size = nr_pages << PAGE_SHIFT;
    for (unsigned int i = 0; i < nr_phys_ranges; i++)
    {
        auto &ranges = phys_ranges[i];

        if (ranges.size >= size)
        {
            auto ret = (void *) ranges.start;
            ranges.start += size;
            ranges.size -= size;

            if (!ranges.size)
            {
                // Clean up if we allocated the whole range
                bootmem_remove_range(i);
            }
#ifdef CONFIG_BOOTMEM_DEBUG
            printf("alloc_boot_page: Allocated [%016lx, %016lx]\n", (unsigned long) ret,
                   (unsigned long) ret + size);
#endif
            return ret;
        }
    }

    panic("alloc_boot_page of %lu pages failed", nr_pages);
}
