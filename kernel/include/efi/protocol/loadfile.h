/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_EFI_PROTOCOL_LOADFILE_H
#define _ONYX_EFI_PROTOCOL_LOADFILE_H

#include <efi/protocol/device-path.h>
#include <efi/types.h>

#define EFI_LOAD_FILE_PROTOCOL_GUID                        \
    {                                                      \
        0x56EC3091, 0x954C, 0x11d2,                        \
        {                                                  \
            0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b \
        }                                                  \
    }

#define EFI_LOAD_FILE2_PROTOCOL_GUID                       \
    {                                                      \
        0x4006c0c1, 0xfcb3, 0x403e,                        \
        {                                                  \
            0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d \
        }                                                  \
    }

struct _EFI_LOAD_FILE_PROTOCOL;

typedef EFI_STATUS(EFIAPI *EFI_LOAD_FILE)(_EFI_LOAD_FILE_PROTOCOL *This,
                                          EFI_DEVICE_PATH_PROTOCOL *FilePath, bool BootPolicy,
                                          size_t *BufferSize, void *Buffer);

typedef struct _EFI_LOAD_FILE_PROTOCOL
{
    EFI_LOAD_FILE LoadFile;
} EFI_LOAD_FILE_PROTOCOL;

typedef EFI_LOAD_FILE_PROTOCOL EFI_LOAD_FILE2_PROTOCOL;

#endif
