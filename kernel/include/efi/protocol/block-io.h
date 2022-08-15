// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_BLOCK_IO_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_BLOCK_IO_H_

#include <onyx/compiler.h>

#include <efi/boot-services.h>
#include <efi/runtime-services.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_BLOCK_IO_PROTOCOL_GUID                         \
    {                                                      \
        0x964e5b21, 0x6459, 0x11d2,                        \
        {                                                  \
            0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b \
        }                                                  \
    }

extern const EFI_GUID BlockIoProtocol;

#define EFI_BLOCK_IO_PROTOCOL_REVISION2 0x00020001
#define EFI_BLOCK_IO_PROTOCOL_REVISION3 0x00020031

typedef struct EFI_BLOCK_IO_MEDIA EFI_BLOCK_IO_MEDIA;
typedef struct EFI_BLOCK_IO_PROTOCOL EFI_BLOCK_IO_PROTOCOL;

struct EFI_BLOCK_IO_PROTOCOL
{
    uint64_t Revision;
    EFI_BLOCK_IO_MEDIA* Media;
    EFI_STATUS (*Reset)(EFI_BLOCK_IO_PROTOCOL* self, bool ExtendedVerification) EFIAPI;
    EFI_STATUS(*ReadBlocks)
    (EFI_BLOCK_IO_PROTOCOL* self, uint32_t MediaId, uint64_t LBA, uint64_t BufferSize,
     void* Buffer) EFIAPI;
    EFI_STATUS(*WriteBlocks)
    (EFI_BLOCK_IO_PROTOCOL* self, uint32_t MediaId, uint64_t LBA, uint64_t BufferSize,
     const void* Buffer) EFIAPI;
    EFI_STATUS (*FlushBlocks)(EFI_BLOCK_IO_PROTOCOL* self);
};

struct EFI_BLOCK_IO_MEDIA
{
    // present in rev1
    uint32_t MediaId;
    bool RemovableMedia;
    bool MediaPresent;
    bool LogicalPartition;
    bool ReadOnly;
    bool WriteCaching;
    uint32_t BlockSize;
    uint32_t IoAlign;
    uint64_t LastBlock;

    // present in rev2
    uint64_t LowestAlignedLba;
    uint32_t LogicalBlocksPerPhysicalBlock;

    // present in rev3
    uint32_t OptimalTransferLengthGranularity;
};

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_BLOCK_IO_H_
