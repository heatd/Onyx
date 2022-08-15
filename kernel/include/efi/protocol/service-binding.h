// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SERVICE_BINDING_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SERVICE_BINDING_H_

#include <onyx/compiler.h>

#include <efi/types.h>

__BEGIN_CDECLS

typedef struct EFI_SERVICE_BINDING_PROTOCOL
{
    EFI_STATUS(*CreateChild)
    (struct EFI_SERVICE_BINDING_PROTOCOL* self, EFI_HANDLE* child_handle) EFIAPI;

    EFI_STATUS(*DestroyChild)
    (struct EFI_SERVICE_BINDING_PROTOCOL* self, EFI_HANDLE child_handle) EFIAPI;
} EFI_SERVICE_BINDING_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SERVICE_BINDING_H_
