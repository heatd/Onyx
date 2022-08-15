// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_DISK_IO_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_DISK_IO_H_

#include <onyx/compiler.h>

#include <efi/boot-services.h>
#include <efi/runtime-services.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_DISK_IO_PROTOCOL_GUID                          \
    {                                                      \
        0xCE345171, 0xBA0B, 0x11d2,                        \
        {                                                  \
            0x8e, 0x4F, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b \
        }                                                  \
    }

extern const EFI_GUID DiskIoProtocol;

#define EFI_DISK_IO_PROTOCOL_REVISION 0x00010000

typedef struct EFI_DISK_IO_PROTOCOL EFI_DISK_IO_PROTOCOL;

struct EFI_DISK_IO_PROTOCOL
{
    uint64_t Revision;
    EFI_STATUS(*ReadDisk)
    (EFI_DISK_IO_PROTOCOL* self, uint32_t MediaId, uint64_t Offset, uint64_t BufferSize,
     void* Buffer) EFIAPI;
    EFI_STATUS(*WriteDisk)
    (EFI_DISK_IO_PROTOCOL* self, uint32_t MediaId, uint64_t Offset, uint64_t BufferSize,
     const void* Buffer) EFIAPI;
};

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_DISK_IO_H_
