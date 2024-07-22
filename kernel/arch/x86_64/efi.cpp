/*
 * Copyright (c) 2018 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/acpi.h>
#include <onyx/page.h>
#include <onyx/paging.h>
#include <onyx/smbios.h>
#include <onyx/types.h>
#include <onyx/vm.h>
#include <onyx/x86/pat.h>

#include <efi/efi.h>
#include <efi/system-table.h>
extern efi_handoff_state efi_state;

/* From Carbon... */
static bool uefi_unusable_region(const EFI_MEMORY_DESCRIPTOR *desc)
{
    /* Based partly on UEFI spec 2.9 "Table 7.6 Memory Type Usage after ExitBootServices()" */

    /* We use it for bootloader/efistub/efi handoff data structures */
    if (desc->Type == EfiLoaderData)
        return true;
    /* Get rid of the boot services' code and data */
    /* TODO: Buggy EFI firmware sometimes touches boot services areas when exiting efi runtime
     * services... We should be able to reserve this until needed.
     */
    if (desc->Type == EfiBootServicesCode)
        return false;
    if (desc->Type == EfiBootServicesData)
        return false;
    if (desc->Type == EfiConventionalMemory)
        return false;

    if (desc->Type == EfiUnusableMemory)
        return true;
    if (desc->Type == EfiReservedMemoryType)
        return true;
    /* Memory mapped I/O is also unusable */
    if (desc->Type == EfiMemoryMappedIO)
        return true;
    if (desc->Type == EfiMemoryMappedIOPortSpace)
        return true;
    /* TODO: Add ways to reclaim ACPI memory */
    if (desc->Type == EfiACPIReclaimMemory)
        return true;
    if (desc->Type == EfiACPIMemoryNVS)
        return true;
    if (desc->Type == EfiRuntimeServicesCode)
        return true;
    if (desc->Type == EfiRuntimeServicesData)
        return true;
    if (desc->Type == EfiPalCode)
        return true;

    return true;
}

static void efi_enumerate_memory_map()
{
    EFI_MEMORY_DESCRIPTOR *descriptors = efi_state.mmap;

    size_t memory = 0;
    unsigned long maxpfn = 0;
    auto entries = efi_state.map_size / efi_state.descriptor_size;
    for (size_t i = 0; i < entries; i++)
    {
        const auto mmap = (EFI_MEMORY_DESCRIPTOR *) x86_placement_map(
            (((unsigned long) descriptors) + (i * efi_state.descriptor_size)));

        if (uefi_unusable_region(mmap))
            continue;

        auto len = mmap->NumberOfPages << PAGE_SHIFT;

        memory += len;
        if (mmap->PhysicalStart == 0)
        {
            mmap->PhysicalStart += PAGE_SIZE;
            mmap->NumberOfPages--;
            len -= PAGE_SIZE;
        }

        if (mmap->PhysicalStart + len > maxpfn)
            maxpfn = mmap->PhysicalStart + len;

        printf("MEMMAP [%lx - %lx]\n", mmap->PhysicalStart, mmap->PhysicalStart + len - 1);

        // Add memory as well
        bootmem_add_range(mmap->PhysicalStart, len);
    }

    maxpfn >>= PAGE_SHIFT;

    printf("efi: Found %zu bytes of usable memory\n", memory);
    printf("MAXPFN: %lx\n", maxpfn);

    paging_map_all_phys();

    page_init(memory, maxpfn);
}

void efi_boot_init(EFI_SYSTEM_TABLE *systable)
{
    efi_enumerate_memory_map();

    if (efi_state.acpi_table)
        acpi_set_rsdp((uintptr_t) efi_state.acpi_table);
    smbios_set_tables((unsigned long) efi_state.smbios_table,
                      (unsigned long) efi_state.smbios30_table);
}

void efi_boot_late_init(EFI_SYSTEM_TABLE *systable)
{
    efi_init((EFI_SYSTEM_TABLE *) PHYS_TO_VIRT(systable),
             (EFI_MEMORY_DESCRIPTOR *) PHYS_TO_VIRT(efi_state.mmap), efi_state.map_size,
             efi_state.descriptor_size, efi_state.descriptor_version);
}
