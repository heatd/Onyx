// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SIMPLE_FILE_SYSTEM_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SIMPLE_FILE_SYSTEM_H_

#include <onyx/compiler.h>

#include <efi/protocol/file.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID               \
    {                                                      \
        0x0964e5b22, 0x6459, 0x11d2,                       \
        {                                                  \
            0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b \
        }                                                  \
    }
extern const EFI_GUID SimpleFileSystemProtocol;

#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION 0x00010000

typedef struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
{
    uint64_t Revision;

    EFI_STATUS(*OpenVolume)
    (struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* self, EFI_FILE_PROTOCOL** root) EFIAPI;
} EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SIMPLE_FILE_SYSTEM_H_
