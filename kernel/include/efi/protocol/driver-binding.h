// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_DRIVER_BINDING_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_DRIVER_BINDING_H_

#include <onyx/compiler.h>

#include <efi/protocol/device-path.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_DRIVER_BINDING_PROTOCOL_GUID                   \
    {                                                      \
        0x18a031ab, 0xb443, 0x4d1a,                        \
        {                                                  \
            0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 \
        }                                                  \
    }
extern const EFI_GUID DriverBindingProtocol;

typedef struct EFI_DRIVER_BINDING_PROTOCOL
{
    EFI_STATUS(*Supported)
    (struct EFI_DRIVER_BINDING_PROTOCOL* self, EFI_HANDLE controller_handle,
     EFI_DEVICE_PATH_PROTOCOL* remaining_path) EFIAPI;

    EFI_STATUS(*Start)
    (struct EFI_DRIVER_BINDING_PROTOCOL* self, EFI_HANDLE controller_handle,
     EFI_DEVICE_PATH_PROTOCOL* remaining_path) EFIAPI;

    EFI_STATUS(*Stop)
    (struct EFI_DRIVER_BINDING_PROTOCOL* self, EFI_HANDLE controller_handle, size_t num_children,
     EFI_HANDLE* child_handle_buf) EFIAPI;

    uint32_t Version;
    EFI_HANDLE ImageHandle;
    EFI_HANDLE DriverBindingHandle;
} EFI_DRIVER_BINDING_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_DRIVER_BINDING_H_
