// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_USB_IO_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_USB_IO_H_

#include <onyx/compiler.h>

#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_USB_IO_PROTOCOL_GUID                           \
    {                                                      \
        0x2b2f68d6, 0x0cd2, 0x44cf,                        \
        {                                                  \
            0x8e, 0x8b, 0xbb, 0xa2, 0x0b, 0x1b, 0x5b, 0x75 \
        }                                                  \
    }
extern const EFI_GUID UsbIoProtocol;

typedef enum
{
    EfiUsbDataIn,
    EfiUsbDataOut,
    EfiUsbNoData
} EFI_USB_DATA_DIRECTION;

#define EFI_USB_NOERROR        0x0000
#define EFI_USB_ERR_NOTEXECUTE 0x0001
#define EFI_USB_ERR_STALL      0x0002
#define EFI_USB_ERR_BUFFER     0x0004
#define EFI_USB_ERR_BABBLE     0x0008
#define EFI_USB_ERR_NAK        0x0010
#define EFI_USB_ERR_CRC        0x0020
#define EFI_USB_ERR_TIMEOUT    0x0040
#define EFI_USB_ERR_BITSTUFF   0x0080
#define EFI_USB_ERR_SYSTEM     0x0100

typedef struct
{
    uint8_t RequestType;
    uint8_t Request;
    uint16_t Value;
    uint16_t Index;
    uint16_t Length;
} EFI_USB_DEVICE_REQUEST;

typedef EFI_STATUS (*EFI_ASYNC_USB_TRANSFER_CALLBACK)(void* Data, size_t DataLength, void* Context,
                                                      uint32_t Status) EFIAPI;

typedef struct
{
    uint8_t Length;
    uint8_t DescriptorType;
    uint16_t BcdUSB;
    uint8_t DeviceClass;
    uint8_t DeviceSubClass;
    uint8_t DeviceProtocol;
    uint8_t MaxPacketSize0;
    uint16_t IdVendor;
    uint16_t IdProduct;
    uint16_t BcdDevice;
    uint8_t StrManufacturer;
    uint8_t StrProduct;
    uint8_t StrSerialNumber;
    uint8_t NumConfigurations;
} EFI_USB_DEVICE_DESCRIPTOR;

typedef struct
{
    uint8_t Length;
    uint8_t DescriptorType;
    uint16_t TotalLength;
    uint8_t NumInterfaces;
    uint8_t ConfigurationValue;
    uint8_t Configuration;
    uint8_t Attributes;
    uint8_t MaxPower;
} EFI_USB_CONFIG_DESCRIPTOR;

typedef struct
{
    uint8_t Length;
    uint8_t DescriptorType;
    uint8_t InterfaceNumber;
    uint8_t AlternateSetting;
    uint8_t NumEndpoints;
    uint8_t InterfaceClass;
    uint8_t InterfaceSubClass;
    uint8_t InterfaceProtocol;
    uint8_t Interface;
} EFI_USB_INTERFACE_DESCRIPTOR;

typedef struct
{
    uint8_t Length;
    uint8_t DescriptorType;
    uint8_t EndpointAddress;
    uint8_t Attributes;
    uint16_t MaxPacketSize;
    uint8_t Interval;
} EFI_USB_ENDPOINT_DESCRIPTOR;

typedef struct EFI_USB_IO_PROTOCOL
{
    EFI_STATUS(*UsbControlTransfer)
    (struct EFI_USB_IO_PROTOCOL* self, EFI_USB_DEVICE_REQUEST* request,
     EFI_USB_DATA_DIRECTION direction, uint32_t timeout, void* data, size_t data_len,
     uint32_t* status) EFIAPI;

    EFI_STATUS(*UsbBulkTransfer)
    (struct EFI_USB_IO_PROTOCOL* self, uint8_t endpoint, void* data, size_t data_len,
     size_t timeout, uint32_t* status) EFIAPI;

    EFI_STATUS(*UsbAsyncInterruptTransfer)
    (struct EFI_USB_IO_PROTOCOL* self, uint8_t endpoint, bool is_new_transfer,
     size_t polling_interval, size_t data_len, EFI_ASYNC_USB_TRANSFER_CALLBACK interrupt_cb,
     void* context) EFIAPI;

    EFI_STATUS(*UsbSyncInterruptTransfer)
    (struct EFI_USB_IO_PROTOCOL* self, uint8_t endpoint, void* data, size_t* data_len,
     size_t timeout, uint32_t* status) EFIAPI;

    EFI_STATUS(*UsbIsochronousTransfer)
    (struct EFI_USB_IO_PROTOCOL* self, uint8_t endpoint, void* data, size_t data_len,
     uint32_t* status) EFIAPI;

    EFI_STATUS(*UsbAsyncIsochronousTransfer)
    (struct EFI_USB_IO_PROTOCOL* self, uint8_t endpoint, void* data, size_t data_len,
     EFI_ASYNC_USB_TRANSFER_CALLBACK isoc_cb, void* context) EFIAPI;

    EFI_STATUS(*UsbGetDeviceDescriptor)
    (struct EFI_USB_IO_PROTOCOL* self, EFI_USB_DEVICE_DESCRIPTOR* descriptor) EFIAPI;

    EFI_STATUS(*UsbGetConfigDescriptor)
    (struct EFI_USB_IO_PROTOCOL* self, EFI_USB_CONFIG_DESCRIPTOR* descriptor) EFIAPI;

    EFI_STATUS(*UsbGetInterfaceDescriptor)
    (struct EFI_USB_IO_PROTOCOL* self, EFI_USB_INTERFACE_DESCRIPTOR* descriptor) EFIAPI;

    EFI_STATUS(*UsbGetEndpointDescriptor)
    (struct EFI_USB_IO_PROTOCOL* self, uint8_t endpt_index,
     EFI_USB_ENDPOINT_DESCRIPTOR* descriptor) EFIAPI;

    EFI_STATUS(*UsbGetStringDescriptor)
    (struct EFI_USB_IO_PROTOCOL* self, uint16_t langid, uint8_t stringid, char16_t** str) EFIAPI;

    EFI_STATUS(*UsbGetSupportedLanguages)
    (struct EFI_USB_IO_PROTOCOL* self, uint16_t** langid_table, uint16_t* table_size) EFIAPI;

    EFI_STATUS (*UsbPortReset)(struct EFI_USB_IO_PROTOCOL* self) EFIAPI;
} EFI_USB_IO_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_USB_IO_H_
