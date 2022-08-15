// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_LOADED_IMAGE_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_LOADED_IMAGE_H_

#include <onyx/compiler.h>

#include <efi/protocol/device-path.h>
#include <efi/system-table.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_LOADED_IMAGE_PROTOCOL_GUID                     \
    {                                                      \
        0x5b1b31a1, 0x9562, 0x11d2,                        \
        {                                                  \
            0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b \
        }                                                  \
    }
extern const EFI_GUID LoadedImageProtocol;

#define EFI_LOADED_IMAGE_PROTOCOL_REVISION 0x1000

typedef struct
{
    uint32_t Revision;
    EFI_HANDLE ParentHandle;
    EFI_SYSTEM_TABLE* SystemTable;
    EFI_HANDLE DeviceHandle;
    EFI_DEVICE_PATH_PROTOCOL* FilePath;
    void* Reserved;
    uint32_t LoadOptionsSize;
    void* LoadOptions;
    void* ImageBase;
    uint64_t ImageSize;
    EFI_MEMORY_TYPE ImageCodeType;
    EFI_MEMORY_TYPE ImageDataType;

    EFI_STATUS (*Unload)(EFI_HANDLE img) EFIAPI;
} EFI_LOADED_IMAGE_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_LOADED_IMAGE_H_
