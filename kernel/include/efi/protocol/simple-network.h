// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SIMPLE_NETWORK_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SIMPLE_NETWORK_H_

#include <stdbool.h>

#include <onyx/compiler.h>

#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_SIMPLE_NETWORK_PROTOCOL_GUID                   \
    {                                                      \
        0xa19832b9, 0xac25, 0x11d3,                        \
        {                                                  \
            0x9a, 0x2d, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d \
        }                                                  \
    }
extern const EFI_GUID SimpleNetworkProtocol;

#define EFI_SIMPLE_NETWORK_PROTOCOL_REVISION 0x00010000

#define MAX_MCAST_FILTER_CNT 16
typedef struct
{
    uint32_t State;
    uint32_t HwAddressSize;
    uint32_t MediaHeaderSize;
    uint32_t MaxPacketSize;
    uint32_t NvRamSize;
    uint32_t NvRamAccessSize;
    uint32_t ReceiveFilterMask;
    uint32_t ReceiveFilterSetting;
    uint32_t MaxMCastFilterCount;
    uint32_t MCastFilterCount;
    EFI_MAC_ADDR MCastFilter[MAX_MCAST_FILTER_CNT];
    EFI_MAC_ADDR CurrentAddress;
    EFI_MAC_ADDR BroadcastAddress;
    EFI_MAC_ADDR PermanentAddress;
    uint8_t IfType;
    bool MacAddressChangeable;
    bool MultipleTxSupported;
    bool MediaPresentSupported;
    bool MediaPresent;
} EFI_SIMPLE_NETWORK_MODE;

typedef enum
{
    EfiSimpleNetworkStopped,
    EfiSimpleNetworkStarted,
    EfiSimpleNetworkInitialized,
    EfiSimpleNetworkMaxState
} EFI_SIMPLE_NETWORK_STATE;

#define EFI_SIMPLE_NETWORK_RECEIVE_UNICAST               0x01
#define EFI_SIMPLE_NETWORK_RECEIVE_MULTICAST             0x02
#define EFI_SIMPLE_NETWORK_RECEIVE_BROADCAST             0x04
#define EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS           0x08
#define EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS_MULTICAST 0x10

typedef struct
{
    uint64_t RxTotalFrames;
    uint64_t RxGoodFrames;
    uint64_t RxUndersizeFrames;
    uint64_t RxOversizeFrames;
    uint64_t RxDroppedFrames;
    uint64_t RxUnicastFrames;
    uint64_t RxBroadcastFrames;
    uint64_t RxMulticastFrames;
    uint64_t RxCrcErrorFrames;
    uint64_t RxTotalBytes;
    uint64_t TxTotalFrames;
    uint64_t TxGoodFrames;
    uint64_t TxUndersizeFrames;
    uint64_t TxOversizeFrames;
    uint64_t TxDroppedFrames;
    uint64_t TxUnicastFrames;
    uint64_t TxBroadcastFrames;
    uint64_t TxMulticastFrames;
    uint64_t TxCrcErrorFrames;
    uint64_t TxTotalBytes;
    uint64_t Collisions;
    uint64_t UnsupportedProtocol;
    uint64_t RxDuplicatedFrames;
    uint64_t RxDecryptErrorFrames;
    uint64_t TxErrorFrames;
    uint64_t TxRetryFrames;
} EFI_NETWORK_STATISTICS;

#define EFI_SIMPLE_NETWORK_RECEIVE_INTERRUPT  0x01
#define EFI_SIMPLE_NETWORK_TRANSMIT_INTERRUPT 0x02
#define EFI_SIMPLE_NETWORK_COMMAND_INTERRUPT  0x04
#define EFI_SIMPLE_NETWORK_SOFTWARE_INTERRUPT 0x08

typedef struct EFI_SIMPLE_NETWORK_PROTOCOL
{
    uint64_t Revision;

    EFI_STATUS (*Start)(struct EFI_SIMPLE_NETWORK_PROTOCOL* self) EFIAPI;

    EFI_STATUS (*Stop)(struct EFI_SIMPLE_NETWORK_PROTOCOL* self) EFIAPI;

    EFI_STATUS(*Initialize)
    (struct EFI_SIMPLE_NETWORK_PROTOCOL* self, size_t extra_rx_buf_size,
     size_t extra_tx_buf_size) EFIAPI;

    EFI_STATUS(*Reset)
    (struct EFI_SIMPLE_NETWORK_PROTOCOL* self, bool extended_verification) EFIAPI;

    EFI_STATUS (*Shutdown)(struct EFI_SIMPLE_NETWORK_PROTOCOL* self) EFIAPI;

    EFI_STATUS(*ReceiveFilters)
    (struct EFI_SIMPLE_NETWORK_PROTOCOL* self, uint32_t enable, uint32_t disable,
     bool reset_mcast_filter, size_t mcast_filter_count, EFI_MAC_ADDR* mcast_filter) EFIAPI;

    EFI_STATUS(*StationAddress)
    (struct EFI_SIMPLE_NETWORK_PROTOCOL* self, bool reset, EFI_MAC_ADDR* new_addr) EFIAPI;

    EFI_STATUS(*Statistics)
    (struct EFI_SIMPLE_NETWORK_PROTOCOL* self, bool reset, size_t* stats_size,
     EFI_NETWORK_STATISTICS* stats_table) EFIAPI;

    EFI_STATUS(*MCastIpToMac)
    (struct EFI_SIMPLE_NETWORK_PROTOCOL* self, bool ipv6, EFI_IP_ADDR* ip,
     EFI_MAC_ADDR* mac) EFIAPI;

    EFI_STATUS(*NvData)
    (struct EFI_SIMPLE_NETWORK_PROTOCOL* self, bool read_write, size_t offset, size_t buf_size,
     void* buf) EFIAPI;

    EFI_STATUS(*GetStatus)
    (struct EFI_SIMPLE_NETWORK_PROTOCOL* self, uint32_t* interrupt_status, void** tx_buf) EFIAPI;

    EFI_STATUS(*Transmit)
    (struct EFI_SIMPLE_NETWORK_PROTOCOL* self, size_t header_size, size_t buf_size, void* buf,
     EFI_MAC_ADDR* src, EFI_MAC_ADDR* dest, uint16_t* protocol) EFIAPI;

    EFI_STATUS(*Receive)
    (struct EFI_SIMPLE_NETWORK_PROTOCOL* self, size_t* header_size, size_t* buf_size, void* buf,
     EFI_MAC_ADDR* src, EFI_MAC_ADDR* dest, uint16_t* protocol) EFIAPI;

    EFI_EVENT WaitForPacket;
    EFI_SIMPLE_NETWORK_MODE* Mode;
} EFI_SIMPLE_NETWORK_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_SIMPLE_NETWORK_H_
