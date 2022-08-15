// Copyright 2022 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SHELL_PARAMETERS_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SHELL_PARAMETERS_H_

#include <onyx/compiler.h>

#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_SHELL_PARAMETERS_PROTOCOL_GUID                 \
    {                                                      \
        0x752f3136, 0x4e16, 0x4fdc,                        \
        {                                                  \
            0xa2, 0x2a, 0xe5, 0xf4, 0x68, 0x12, 0xf4, 0xca \
        }                                                  \
    }

typedef struct
{
    char16_t** Argv;
    size_t Argc;
    EFI_HANDLE StdIn;
    EFI_HANDLE StdOut;
    EFI_HANDLE StdErr;
} EFI_SHELL_PARAMETERS_PROTOCOL;

extern const EFI_GUID ShellParametersProtocol;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SHELL_PARAMETERS_H_
