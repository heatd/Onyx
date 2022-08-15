// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_FILE_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_FILE_H_

#include <onyx/compiler.h>

#include <efi/boot-services.h>
#include <efi/runtime-services.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_FILE_PROTOCOL_REVISION        0x00010000
#define EFI_FILE_PROTOCOL_REVISION2       0x00020000
#define EFI_FILE_PROTOCOL_LATEST_REVISION EFI_FILE_PROTOCOL_REVISION2

#define EFI_FILE_MODE_READ   0x0000000000000001
#define EFI_FILE_MODE_WRITE  0x0000000000000002
#define EFI_FILE_MODE_CREATE 0x8000000000000000

#define EFI_FILE_READ_ONLY  0x0000000000000001
#define EFI_FILE_HIDDEN     0x0000000000000002
#define EFI_FILE_SYSTEM     0x0000000000000004
#define EFI_FILE_RESERVED   0x0000000000000008
#define EFI_FILE_DIRECTORY  0x0000000000000010
#define EFI_FILE_ARCHIVE    0x0000000000000020
#define EFI_FILE_VALID_ATTR 0x0000000000000037

typedef struct
{
    EFI_EVENT Event;
    EFI_STATUS Status;
    size_t BufferSize;
    void* Buffer;
} EFI_FILE_IO_TOKEN;

#define EFI_FILE_INFO_GUID                                 \
    {                                                      \
        0x09576e92, 0x6d3f, 0x11d2,                        \
        {                                                  \
            0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b \
        }                                                  \
    }
extern const EFI_GUID FileInfoGuid;

typedef struct
{
    uint64_t Size;
    uint64_t FileSize;
    uint64_t PhysicalSize;
    EFI_TIME CreateTime;
    EFI_TIME LastAccessTime;
    EFI_TIME ModificationTime;
    uint64_t Attribute;
    char16_t FileName[];
} EFI_FILE_INFO;

#define EFI_FILE_SYSTEM_INFO_GUID                          \
    {                                                      \
        0x09576e93, 0x6d3f, 0x11d2,                        \
        {                                                  \
            0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b \
        }                                                  \
    }
extern const EFI_GUID FileSystemInfoGuid;

typedef struct
{
    uint64_t Size;
    bool ReadOnly;
    uint64_t VolumeSize;
    uint64_t FreeSpace;
    uint32_t BlockSize;
    char16_t* VolumeLabel[];
} EFI_FILE_SYSTEM_INFO;

typedef struct EFI_FILE_PROTOCOL
{
    uint64_t Revision;

    EFI_STATUS(*Open)
    (struct EFI_FILE_PROTOCOL* self, struct EFI_FILE_PROTOCOL** new_handle,
     const char16_t* filename, uint64_t open_mode, uint64_t attributes) EFIAPI;

    EFI_STATUS (*Close)(struct EFI_FILE_PROTOCOL* self) EFIAPI;

    EFI_STATUS (*Delete)(struct EFI_FILE_PROTOCOL* self) EFIAPI;

    EFI_STATUS (*Read)(struct EFI_FILE_PROTOCOL* self, size_t* len, void* buf) EFIAPI;

    EFI_STATUS (*Write)(struct EFI_FILE_PROTOCOL* self, size_t* len, const void* buf) EFIAPI;

    EFI_STATUS (*GetPosition)(struct EFI_FILE_PROTOCOL* self, uint64_t* position) EFIAPI;

    EFI_STATUS (*SetPosition)(struct EFI_FILE_PROTOCOL* self, uint64_t position) EFIAPI;

    EFI_STATUS(*GetInfo)
    (struct EFI_FILE_PROTOCOL* self, const EFI_GUID* info_type, size_t* buf_size, void* buf) EFIAPI;

    EFI_STATUS(*SetInfo)
    (struct EFI_FILE_PROTOCOL* self, const EFI_GUID* info_type, size_t buf_size, void* buf) EFIAPI;

    EFI_STATUS (*Flush)(struct EFI_FILE_PROTOCOL* self) EFIAPI;

    EFI_STATUS(*OpenEx)
    (struct EFI_FILE_PROTOCOL* self, struct EFI_FILE_PROTOCOL* new_handle, char16_t* filename,
     uint64_t open_mode, uint64_t attributes, EFI_FILE_IO_TOKEN* token) EFIAPI;

    EFI_STATUS (*ReadEx)(struct EFI_FILE_PROTOCOL* self, EFI_FILE_IO_TOKEN* token) EFIAPI;

    EFI_STATUS (*WriteEx)(struct EFI_FILE_PROTOCOL* self, EFI_FILE_IO_TOKEN* token) EFIAPI;

    EFI_STATUS (*FlushEx)(struct EFI_FILE_PROTOCOL* self, EFI_FILE_IO_TOKEN* token) EFIAPI;
} EFI_FILE_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_FILE_H_
