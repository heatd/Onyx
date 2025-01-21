/*
 * Copyright (c) 2022 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define pr_fmt(fmt) "efi: " fmt

#include <stdio.h>

#include <onyx/err.h>
#include <onyx/mm/slab.h>
#include <onyx/process.h>
#include <onyx/utf8.h>
#include <onyx/utfstring.h>
#include <onyx/vm.h>

#include <efi/efi.h>

static mm_address_space *efi_aspace;

namespace efi::internal
{
static EFI_SYSTEM_TABLE *system_table;

} // namespace efi::internal

// Idea stolen from Zircon
/**
 * @brief Guard efi accesses and calls with proper address space setting
 *
 */
class efi_guard
{
    mm_address_space *old_aspace;

public:
    efi_guard()
    {
        old_aspace = vm_set_aspace(efi_aspace);
    }

    EFI_SYSTEM_TABLE *system_table() const
    {
        return efi::internal::system_table;
    }

    ~efi_guard()
    {
        vm_set_aspace(old_aspace);
    }
};

/**
 * @brief Calculates VM flags from EFI memory region attributes
 *
 * @param attributes EFI memory region attributes
 * @return VM flags
 */
unsigned long efi_memory_desc_flags_to_vm(uint64_t attributes)
{
    unsigned long flags = VM_EXEC | VM_NOFLUSH;
    if (attributes & EFI_MEMORY_RO)
        flags |= VM_READ;
    else
        flags |= VM_WRITE | VM_READ;

    if (attributes & EFI_MEMORY_UC)
        flags |= VM_NOCACHE;
    else if (attributes & EFI_MEMORY_WP)
        flags |= VM_WP;
    else if (attributes & EFI_MEMORY_WC)
        flags |= VM_WC;
    else if (attributes & EFI_MEMORY_WT)
        flags |= VM_WRITETHROUGH;

    if (attributes & EFI_MEMORY_RP)
        flags &= ~VM_READ;

    if (attributes & EFI_MEMORY_XP)
        flags &= ~VM_EXEC;

    return flags;
}

/**
 * @brief Remap a EFI region to the efi address space
 *
 * @param desc Memory descriptor to map
 */
void efi_remap_efi_region(EFI_MEMORY_DESCRIPTOR &desc)
{
    pr_warn("Remapping [%016lx, %016lx]\n", desc.PhysicalStart,
            desc.PhysicalStart + (desc.NumberOfPages << PAGE_SHIFT) - 1);
    bool mapping_over_null = desc.PhysicalStart == 0;

    auto flags = efi_memory_desc_flags_to_vm(desc.Attribute);
    auto ptr =
        __map_pages_to_vaddr(efi_aspace, (void *) desc.PhysicalStart, (void *) desc.PhysicalStart,
                             desc.NumberOfPages << PAGE_SHIFT, flags);
    desc.VirtualStart = desc.PhysicalStart;
    if (!ptr && !mapping_over_null)
        panic("Failed to map EFI region [%016lx, %016lx] attributes %016lx\n", desc.PhysicalStart,
              desc.PhysicalStart + (desc.NumberOfPages << PAGE_SHIFT) - 1, desc.Attribute);
    if (mapping_over_null)
    {
        pr_warn("Firmware mapped over the zero page. Due to limitations in kernel internal APIs, "
                "we don't know if this failed due to an OOM.\n");
    }
}

/**
 * @brief Map the NULL pointer page to EFI's address space
 *
 */
void efi_quirk_map_zero_region()
{
    __map_pages_to_vaddr(efi_aspace, nullptr, nullptr, PAGE_SIZE, VM_READ | VM_NOFLUSH);
}

/**
 * @brief Print information about UEFI to the system log
 *
 */
static void efi_print_info()
{
    // XXX We cannot use efi_guard here as it blows up using asan. and disabling asan for the func
    // doesn't work because we print it right away.
    auto st = efi::internal::system_table;
    char16_t *fv = (char16_t *) PHYS_TO_VIRT(st->FirmwareVendor);
    auto str = string_from_ucs2str((utf16_t *) fv).value_or("<error decoding ucs2>");
    str.append(" ");

    const auto runtime_services_rev =
        ((EFI_RUNTIME_SERVICES *) PHYS_TO_VIRT(st->RuntimeServices))->Hdr.Revision;
    printf("efi: EFI v%u.%u by %s rev %u.%u\n", runtime_services_rev >> 16,
           runtime_services_rev & 0xffff, str.c_str(), st->FirmwareRevision >> 16,
           st->FirmwareRevision & 0xffff);
}

static void efi_dump_mem_desc(const EFI_MEMORY_DESCRIPTOR *desc)
{
    pr_warn(
        "Descriptor type %u physical start %lx virtual start %lx nr_pages %lx attributes %08lx\n",
        desc->Type, desc->PhysicalStart, desc->VirtualStart, desc->NumberOfPages, desc->Attribute);
}

#define EFI_RESERVED_TYPE               0
#define EFI_LOADER_CODE                 1
#define EFI_LOADER_DATA                 2
#define EFI_BOOT_SERVICES_CODE          3
#define EFI_BOOT_SERVICES_DATA          4
#define EFI_RUNTIME_SERVICES_CODE       5
#define EFI_RUNTIME_SERVICES_DATA       6
#define EFI_CONVENTIONAL_MEMORY         7
#define EFI_UNUSABLE_MEMORY             8
#define EFI_ACPI_RECLAIM_MEMORY         9
#define EFI_ACPI_MEMORY_NVS             10
#define EFI_MEMORY_MAPPED_IO            11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE 12
#define EFI_PAL_CODE                    13
#define EFI_PERSISTENT_MEMORY           14
#define EFI_UNACCEPTED_MEMORY           15
#define EFI_MAX_MEMORY_TYPE             16

static bool should_map_efi(const EFI_MEMORY_DESCRIPTOR *desc)
{
    if (desc->Attribute & EFI_MEMORY_RUNTIME)
        return true;

    /* Some runtime services like touching boot services memory on SVAM. Let's map it just for them,
     * as a hack. */
    switch (desc->Type)
    {
        case EFI_BOOT_SERVICES_CODE:
        case EFI_BOOT_SERVICES_DATA:
            return true;
    }

    return false;
}
/**
 * @brief Initializes EFI
 *
 * @param system_table EFI system table
 * @param descriptors EFI memory map
 * @param mmap_size Size of the memory map, in bytes
 * @param descriptor_size Size of each descriptor, in bytes
 * @param descriptor_version Version of the memory map
 */
NO_ASAN
void efi_init(EFI_SYSTEM_TABLE *system_table, EFI_MEMORY_DESCRIPTOR *descriptors,
              uint32_t mmap_size, uint32_t descriptor_size, uint32_t descriptor_version)
{
    // XXX efi_guard is currently incompatible with ASAN. Maybe we could sync top-level PGD entries
    // in the page fault handler, lazily?

    efi_set_enabled();

    efi::internal::system_table = system_table;
    efi_aspace = mm_create();
    CHECK(!IS_ERR(efi_aspace));
    // EFI firmware out in the wild frequently "accidentally" touch NULL,
    // such that we need to map NULL
    efi_quirk_map_zero_region();

    size_t nr_descriptors = mmap_size / descriptor_size;
    EFI_MEMORY_DESCRIPTOR *desc = descriptors;
    EFI_MEMORY_DESCRIPTOR *map = NULL;
    size_t nr_maps = 0;

#define efi_mmap_ptr(base, idx, desc_size) \
    ((EFI_MEMORY_DESCRIPTOR *) (((u8 *) (base)) + (idx) * (desc_size)))

    for (size_t i = 0; i < nr_descriptors;
         desc = (EFI_MEMORY_DESCRIPTOR *) ((char *) desc + descriptor_size), i++)
    {
#ifdef CONFIG_EFI_DUMP_MEMMAP
        efi_dump_mem_desc(desc);
#endif
        if (should_map_efi(desc))
        {
            nr_maps++;
            EFI_MEMORY_DESCRIPTOR *newmap =
                (EFI_MEMORY_DESCRIPTOR *) kreallocarray(map, nr_maps, descriptor_size, GFP_ATOMIC);
            CHECK(newmap != NULL);
            efi_remap_efi_region(*desc);
            memcpy(efi_mmap_ptr(newmap, nr_maps - 1, descriptor_size), desc, descriptor_size);
            map = newmap;
        }
    }

    {
        efi_guard g;

        EFI_STATUS st = g.system_table()->RuntimeServices->SetVirtualAddressMap(
            nr_maps * descriptor_size, descriptor_size, descriptor_version, map);
        assert(st == EFI_SUCCESS);
    }

    efi_print_info();
}

static bool enabled;

bool efi_enabled()
{
    return enabled;
}

void efi_set_enabled()
{
    enabled = true;
}
