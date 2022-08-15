// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SIMPLE_TEXT_INPUT_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SIMPLE_TEXT_INPUT_H_

#include <onyx/compiler.h>

#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID                \
    {                                                      \
        0x387477c1, 0x69c7, 0x11d2,                        \
        {                                                  \
            0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b \
        }                                                  \
    }
extern const EFI_GUID SimpleTextInputProtocol;

typedef struct
{
    uint16_t ScanCode;
    char16_t UnicodeChar;
} EFI_INPUT_KEY;

typedef struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL
{
    EFI_STATUS(*Reset)
    (struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL* self, bool extendend_verification) EFIAPI;

    EFI_STATUS(*ReadKeyStroke)
    (struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL* self, EFI_INPUT_KEY* key) EFIAPI;

    EFI_EVENT WaitForKey;
} EFI_SIMPLE_TEXT_INPUT_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SIMPLE_TEXT_INPUT_H_
