/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_EFI_EFI_H
#define _ONYX_EFI_EFI_H

#include <efi/system-table.h>

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
              uint32_t mmap_size, uint32_t descriptor_size, uint32_t descriptor_version);

struct efi_handoff_state
{
    EFI_MEMORY_DESCRIPTOR *mmap;
    size_t map_size;
    size_t map_key;
    size_t descriptor_size;
    size_t descriptor_version;
    const void *acpi_table;
    const void *smbios_table;
    const void *smbios30_table;
};

void efi_boot_init(EFI_SYSTEM_TABLE *systable);
void efi_boot_late_init(EFI_SYSTEM_TABLE *systable);

#ifndef CONFIG_EFI
static inline bool efi_enabled()
{
    return false;
}
#else
bool efi_enabled();
#endif

void efi_set_enabled();

#endif
