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
#include <efi/protocol/initrd.h>
#include <efi/protocol/loadfile.h>
#include <efi/runtime-services.h>
#include <efi/system-table.h>

#define BOOT_SECTION [[gnu::no_instrument_function, gnu::section(".boot")]]

extern char __kernel_size[];

extern "C" BOOT_SECTION void efi_relocate(EFI_SYSTEM_TABLE *table)
{
    EFI_BOOT_SERVICES *bs = table->BootServices;
    EFI_PHYSICAL_ADDR addr = 0xffffffff;

    addr = UINT32_MAX;

    const size_t ksize = (size_t) &__kernel_size;
    auto pages = ksize >> PAGE_SHIFT;

    if (ksize & (PAGE_SIZE - 1))
        pages++;

    EFI_STATUS st = bs->AllocatePages(AllocateMaxAddress, EfiReservedMemoryType, pages, &addr);
    (void) st;
}

[[gnu::section(".boot.data")]] const EFI_GUID loadfile2_guid = EFI_LOAD_FILE2_PROTOCOL_GUID;

EFI_STATUS efistub_load_initrd(EFI_SYSTEM_TABLE *systab)
{
    EFI_DEVICE_PATH_PROTOCOL *path;
    EFI_HANDLE path_handle;
    EFI_LOAD_FILE2_PROTOCOL *loadfile_pp;
    const auto bs = systab->BootServices;
    const EFI_GUID linux_initrd_guid = EFI_INITRD_MEDIA_GUID;

    // First locate the handle and protocol pointer for the given device path
    EFI_STATUS st = bs->LocateDevicePath(&linux_initrd_guid, &path, &path_handle);

    if (st < 0)
        return EFI_NOT_FOUND;

    // Get the LOADFILE2 protocol for the path handle
    st = bs->HandleProtocol(path_handle, &loadfile2_guid, (void **) &loadfile_pp);

    if (st < 0)
        return EFI_NOT_FOUND;
    return EFI_SUCCESS;
}

extern "C" BOOT_SECTION void efistub_main(EFI_SYSTEM_TABLE *table)
{
    if (efistub_load_initrd(table) != EFI_SUCCESS)
        __asm__ __volatile("int3");
}
