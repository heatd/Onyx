// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_DEVICE_PATH_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_DEVICE_PATH_H_

#include <onyx/compiler.h>

#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_DEVICE_PATH_PROTOCOL_GUID                      \
    {                                                      \
        0x09576e91, 0x6d3f, 0x11d2,                        \
        {                                                  \
            0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b \
        }                                                  \
    }
extern const EFI_GUID DevicePathProtocol;

typedef struct EFI_DEVICE_PATH_PROTOCOL
{
    uint8_t Type;
    uint8_t SubType;
    uint8_t Length[2];
} EFI_DEVICE_PATH_PROTOCOL;

#define DEVICE_PATH_HARDWARE       0x01
#define DEVICE_PATH_ACPI           0x02
#define DEVICE_PATH_MESSAGING      0x03
#define DEVICE_PATH_MEDIA          0x04
#define DEVICE_PATH_BIOS_BOOT_SPEC 0x05
#define DEVICE_PATH_END            0x7f

#define DEVICE_PATH_INSTANCE_END 0x01
#define DEVICE_PATH_ENTIRE_END   0xff

#define DEVICE_PATH_HW_PCI        0x01
#define DEVICE_PATH_HW_PCCARD     0x02
#define DEVICE_PATH_HW_MEMMAP     0x03
#define DEVICE_PATH_HW_VENDOR     0x04
#define DEVICE_PATH_HW_CONTROLLER 0x05
#define DEVICE_PATH_HW_BMC        0x06

#define DEVICE_PATH_MESSAGING_ATAPI            0x01
#define DEVICE_PATH_MESSAGING_SCSI             0x02
#define DEVICE_PATH_MESSAGING_FIBRE_CHANNEL    0x03
#define DEVICE_PATH_MESSAGING_1394             0x04
#define DEVICE_PATH_MESSAGING_USB              0x05
#define DEVICE_PATH_MESSAGING_I2O              0x06
#define DEVICE_PATH_MESSAGING_INFINIBAND       0x09
#define DEVICE_PATH_MESSAGING_VENDOR           0x0a
#define DEVICE_PATH_MESSAGING_MAC              0x0b
#define DEVICE_PATH_MESSAGING_IPV4             0x0c
#define DEVICE_PATH_MESSAGING_IPV6             0x0d
#define DEVICE_PATH_MESSAGING_UART             0x0e
#define DEVICE_PATH_MESSAGING_USB_CLASS        0x0f
#define DEVICE_PATH_MESSAGING_USB_WWID         0x10
#define DEVICE_PATH_MESSAGING_USB_LUN          0x11
#define DEVICE_PATH_MESSAGING_SATA             0x12
#define DEVICE_PATH_MESSAGING_VLAN             0x14
#define DEVICE_PATH_MESSAGING_FIBRE_CHANNEL_EX 0x15

// TODO: sub-types for other types (ACPI, etc)

// TODO: move this to another header? would break circular dependencies between
// boot-services.h and this header, for EFI_MEMORY_TYPE
typedef struct
{
    EFI_DEVICE_PATH_PROTOCOL Header;
    EFI_MEMORY_TYPE MemoryType;
    EFI_PHYSICAL_ADDR StartAddress;
    EFI_PHYSICAL_ADDR EndAddress;
} EFI_DEVICE_PATH_HW_MEMMAP;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_DEVICE_PATH_H_
