// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_SYSTEM_TABLE_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_SYSTEM_TABLE_H_

#include <stdint.h>

#include <onyx/compiler.h>

#include <efi/boot-services.h>
#include <efi/protocol/simple-text-input.h>
#include <efi/protocol/simple-text-output.h>
#include <efi/runtime-services.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_SYSTEM_TABLE_SIGNATURE     0x5453595320494249
#define EFI_2_60_SYSTEM_TABLE_REVISION ((2 << 16) | (60))
#define EFI_2_50_SYSTEM_TABLE_REVISION ((2 << 16) | (50))
#define EFI_2_40_SYSTEM_TABLE_REVISION ((2 << 16) | (40))
#define EFI_2_31_SYSTEM_TABLE_REVISION ((2 << 16) | (31))
#define EFI_2_30_SYSTEM_TABLE_REVISION ((2 << 16) | (30))
#define EFI_2_20_SYSTEM_TABLE_REVISION ((2 << 16) | (20))
#define EFI_2_10_SYSTEM_TABLE_REVISION ((2 << 16) | (10))
#define EFI_2_00_SYSTEM_TABLE_REVISION ((2 << 16) | (00))
#define EFI_1_10_SYSTEM_TABLE_REVISION ((1 << 16) | (10))
#define EFI_1_02_SYSTEM_TABLE_REVISION ((1 << 16) | (02))
#define EFI_SPECIFICATION_VERSION      EFI_SYSTEM_TABLE_REVISION
#define EFI_SYSTEM_TABLE_REVISION      EFI_2_60_SYSTEM_TABLE_REVISION

typedef struct
{
    EFI_GUID VendorGuid;
    const void* VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef struct EFI_SYSTEM_TABLE
{
    EFI_TABLE_HEADER Hdr;
    char16_t* FirmwareVendor;
    uint32_t FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL* ConIn;
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* ConOut;
    EFI_HANDLE StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* StdErr;
    EFI_RUNTIME_SERVICES* RuntimeServices;
    EFI_BOOT_SERVICES* BootServices;
    size_t NumberOfTableEntries;
    const EFI_CONFIGURATION_TABLE* ConfigurationTable;
} EFI_SYSTEM_TABLE;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_SYSTEM_TABLE_H_
