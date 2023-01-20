/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/compiler.h>
#include <onyx/vm.h>

#include <efi/boot-services.h>
#include <efi/runtime-services.h>
#include <efi/system-table.h>

#define BOOT_SECTION [[gnu::no_instrument_function, gnu::section(".boot")]]

extern char __kernel_size[];

extern "C" BOOT_SECTION void efi_relocate(EFI_SYSTEM_TABLE *table)
{
#if 0
    EFI_BOOT_SERVICES *bs = table->BootServices;
    EFI_PHYSICAL_ADDR addr;

    addr = UINT32_MAX;

    const size_t ksize = (size_t) &__kernel_size;
    auto pages = ksize >> PAGE_SHIFT;

    if (ksize & (PAGE_SIZE - 1))
        pages++;

    // bs->AllocatePages(AllocateMaxAddress, EfiReservedMemoryType, pages, )
#endif
}
