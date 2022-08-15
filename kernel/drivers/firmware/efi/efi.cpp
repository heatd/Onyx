/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>

#include <onyx/process.h>
#include <onyx/utf8.h>
#include <onyx/utfstring.h>
#include <onyx/vm.h>
#include <onyx/x86/include/platform/vm.h>

#include <efi/efi.h>

static ref_guard<mm_address_space> efi_aspace;

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
        old_aspace = vm_set_aspace(efi_aspace.get());
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
    printf("efi: Remapping [%016lx, %016lx]\n", desc.PhysicalStart,
           desc.PhysicalStart + (desc.NumberOfPages << PAGE_SHIFT) - 1);
    auto flags = efi_memory_desc_flags_to_vm(desc.Attribute);
    auto ptr =
        __map_pages_to_vaddr(efi_aspace.get(), (void *) desc.PhysicalStart,
                             (void *) desc.PhysicalStart, desc.NumberOfPages << PAGE_SHIFT, flags);
    desc.VirtualStart = desc.PhysicalStart;
    if (!ptr)
        panic("Failed to map EFI region [%016lx, %016lx] attributes %016lx\n", desc.PhysicalStart,
              desc.PhysicalStart + (desc.NumberOfPages << PAGE_SHIFT) - 1, desc.Attribute);
}

/**
 * @brief Map the NULL pointer page to EFI's address space
 *
 */
void efi_quirk_map_zero_region()
{
    __map_pages_to_vaddr(efi_aspace.get(), nullptr, nullptr, PAGE_SIZE, VM_READ | VM_NOFLUSH);
}

/**
 * @brief Print information about UEFI to the system log
 *
 */
static void efi_print_info()
{
    efi_guard g;
    auto st = g.system_table();
    char16_t *fv = st->FirmwareVendor;
    auto str = string_from_ucs2str((utf16_t *) fv).value_or("<error decoding ucs2>");
    str.append(" ");

    const auto runtime_services_rev = st->RuntimeServices->Hdr.Revision;
    printf("efi: EFI v%u.%u by %s rev %u.%u\n", runtime_services_rev >> 16,
           runtime_services_rev & 0xffff, str.c_str(), st->FirmwareRevision >> 16,
           st->FirmwareRevision & 0xffff);
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
void efi_init(EFI_SYSTEM_TABLE *system_table, EFI_MEMORY_DESCRIPTOR *descriptors,
              uint32_t mmap_size, uint32_t descriptor_size, uint32_t descriptor_version)
{
    efi::internal::system_table = system_table;
    efi_aspace = mm_address_space::create().unwrap();
    // EFI firmware out in the wild frequently "accidentally" touch NULL,
    // such that we need to map NULL
    efi_quirk_map_zero_region();

    size_t nr_descriptors = mmap_size / descriptor_size;
    EFI_MEMORY_DESCRIPTOR *desc = descriptors;
    for (size_t i = 0; i < nr_descriptors;
         desc = (EFI_MEMORY_DESCRIPTOR *) ((char *) desc + descriptor_size), i++)
    {
        if (desc->Attribute & EFI_MEMORY_RUNTIME)
        {
            efi_remap_efi_region(*desc);
        }
    }

    {
        efi_guard g;

        EFI_STATUS st = g.system_table()->RuntimeServices->SetVirtualAddressMap(
            mmap_size, descriptor_size, descriptor_version, descriptors);
        assert(st == EFI_SUCCESS);
    }

    efi_print_info();
}
