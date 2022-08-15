// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_PCI_ROOT_BRIDGE_IO_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_PCI_ROOT_BRIDGE_IO_H_

#include <onyx/compiler.h>

#include <efi/boot-services.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_GUID               \
    {                                                      \
        0x2f707ebb, 0x4a1a, 0x11D4,                        \
        {                                                  \
            0x9a, 0x38, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d \
        }                                                  \
    }
extern const EFI_GUID PciRootBridgeIoProtocol;

typedef enum
{
    EfiPciWidthUint8,
    EfiPciWidthUint16,
    EfiPciWidthUint32,
    EfiPciWidthUint64,
    EfiPciWidthFifoUint8,
    EfiPciWidthFifoUint16,
    EfiPciWidthFifoUint32,
    EfiPciWidthFifoUint64,
    EfiPciWidthFillUint8,
    EfiPciWidthFillUint16,
    EfiPciWidthFillUint32,
    EfiPciWidthFillUint64,
    EfiPciWidthMaximum,
} EFI_PCI_ROOT_BRIDGE_IO_WIDTH;

struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL;

typedef struct
{
    EFI_STATUS(*Read)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, EFI_PCI_ROOT_BRIDGE_IO_WIDTH width,
     uint64_t addr, size_t count, void* buffer) EFIAPI;
    EFI_STATUS(*Write)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, EFI_PCI_ROOT_BRIDGE_IO_WIDTH width,
     uint64_t addr, size_t count, void* buffer) EFIAPI;
} EFI_PCI_ROOT_BRIDGE_IO_ACCESS;

#define EFI_PCI_ATTRIBUTE_ISA_MOTHERBOARD_IO   0x0001
#define EFI_PCI_ATTRIBUTE_ISA_IO               0x0002
#define EFI_PCI_ATTRIBUTE_VGA_PALETTE_IO       0x0004
#define EFI_PCI_ATTRIBUTE_VGA_MEMORY           0x0008
#define EFI_PCI_ATTRIBUTE_VGA_IO               0x0010
#define EFI_PCI_ATTRIBUTE_IDE_PRIMARY_IO       0x0020
#define EFI_PCI_ATTRIBUTE_IDE_SECONDARY_IO     0x0040
#define EFI_PCI_ATTRIBUTE_MEMORY_WRITE_COMBINE 0x0080
#define EFI_PCI_ATTRIBUTE_MEMORY_CACHED        0x0800
#define EFI_PCI_ATTRIBUTE_MEMORY_DISABLE       0x1000
#define EFI_PCI_ATTRIBUTE_DUAL_ADDRESS_CYCLE   0x8000
#define EFI_PCI_ATTRIBUTE_ISA_IO_16            0x10000
#define EFI_PCI_ATTRIBUTE_VGA_PALETTE_IO_16    0x20000
#define EFI_PCI_ATTRIBUTE_VGA_IO_16            0x40000

typedef enum
{
    EfiPciOperationBusMasterRead,
    EfiPciOperationBusMasterWrite,
    EfiPciOperationBusMasterCommonBuffer,
    EfiPciOperationBusMasterRead64,
    EfiPciOperationBusMasterWrite64,
    EfiPciOperationBusMasterCommonBuffer64,
    EfiPciOperationMaximum,
} EFI_PCI_ROOT_BRIDGE_IO_OPERATION;

typedef struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL
{
    EFI_HANDLE ParentHandle;

    EFI_STATUS(*PollMem)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, EFI_PCI_ROOT_BRIDGE_IO_WIDTH width,
     uint64_t addr, uint64_t mask, uint64_t value, uint64_t delay, uint64_t* result) EFIAPI;

    EFI_STATUS(*PollIo)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, EFI_PCI_ROOT_BRIDGE_IO_WIDTH width,
     uint64_t addr, uint64_t mask, uint64_t value, uint64_t delay, uint64_t* result) EFIAPI;

    EFI_PCI_ROOT_BRIDGE_IO_ACCESS Mem;
    EFI_PCI_ROOT_BRIDGE_IO_ACCESS Io;
    EFI_PCI_ROOT_BRIDGE_IO_ACCESS Pci;

    EFI_STATUS(*CopyMem)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, EFI_PCI_ROOT_BRIDGE_IO_WIDTH width,
     uint64_t dest_addr, uint64_t src_addr, size_t count) EFIAPI;

    EFI_STATUS(*Map)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, EFI_PCI_ROOT_BRIDGE_IO_OPERATION operation,
     void* host_addr, size_t* num_bytes, EFI_PHYSICAL_ADDR* device_addr, void** mapping) EFIAPI;

    EFI_STATUS (*Unmap)(struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, void* mapping) EFIAPI;

    EFI_STATUS(*AllocateBuffer)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, EFI_ALLOCATE_TYPE type,
     EFI_MEMORY_TYPE memory_type, size_t pages, void** host_addr, uint64_t attributes) EFIAPI;

    EFI_STATUS(*FreeBuffer)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, size_t pages, void* host_addr) EFIAPI;

    EFI_STATUS (*Flush)(struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self) EFIAPI;

    EFI_STATUS(*GetAttributes)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, uint64_t* supports, uint64_t* attributes) EFIAPI;

    EFI_STATUS(*SetAttributes)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, uint64_t attributes, uint64_t* resource_base,
     uint64_t* resource_len) EFIAPI;

    EFI_STATUS(*Configuration)
    (struct EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* self, void** resources) EFIAPI;

    uint32_t SegmentNumber;
} EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_PCI_ROOT_BRIDGE_IO_H_
