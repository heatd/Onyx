// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_MANAGED_NETWORK_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_MANAGED_NETWORK_H_

#include <onyx/compiler.h>

#include <efi/protocol/simple-network.h>
#include <efi/runtime-services.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_MANAGED_NETWORK_PROTOCOL_GUID                  \
    {                                                      \
        0x7ab33a91, 0xace5, 0x4326,                        \
        {                                                  \
            0xb5, 0x72, 0xe7, 0xee, 0x33, 0xd3, 0x9f, 0x16 \
        }                                                  \
    }
extern const EFI_GUID ManagedNetworkProtocol;

typedef struct
{
    EFI_TIME Timestamp;
    EFI_EVENT RecycleEvent;
    uint32_t PacketLength;
    uint32_t HeaderLength;
    uint32_t AddressLength;
    uint32_t DataLength;
    bool BroadcastFlag;
    bool MulticastFlag;
    bool PromiscuousFlag;
    uint16_t ProtocolType;
    void* DestinationAddress;
    void* SourceAddress;
    void* MediaHeader;
    void* PacketData;
} EFI_MANAGED_NETWORK_RECEIVE_DATA;

typedef struct
{
    uint32_t FragmentLength;
    void* FragmentBuffer;
} EFI_MANAGED_NETWORK_FRAGMENT_DATA;

typedef struct
{
    EFI_MAC_ADDR* DestinationAddress;
    EFI_MAC_ADDR* SourceAddress;
    uint16_t ProtocolType;
    uint32_t DataLength;
    uint16_t HeaderLength;
    uint16_t FragmentCount;
    EFI_MANAGED_NETWORK_FRAGMENT_DATA FragmentTable[1];
} EFI_MANAGED_NETWORK_TRANSMIT_DATA;

typedef struct
{
    uint32_t ReceivedQueueTimeoutValue;
    uint32_t TransmitQueueTimeoutValue;
    uint16_t ProtocolTypeFilter;
    bool EnableUnicastReceive;
    bool EnableMulticastReceive;
    bool EnableBroadcastReceive;
    bool EnablePromiscuousReceive;
    bool FlushQueuesOnReset;
    bool EnableReceiveTimestamps;
    bool DisableBackgroundPolling;
} EFI_MANAGED_NETWORK_CONFIG_DATA;

typedef struct
{
    EFI_EVENT Event;
    EFI_STATUS Status;
    union {
        EFI_MANAGED_NETWORK_RECEIVE_DATA* RxData;
        EFI_MANAGED_NETWORK_TRANSMIT_DATA* TxData;
    } Packet;
} EFI_MANAGED_NETWORK_SYNC_COMPLETION_TOKEN;

typedef struct EFI_MANAGED_NETWORK_PROTOCOL
{
    EFI_STATUS(*GetModeData)
    (struct EFI_MANAGED_NETWORK_PROTOCOL* self, EFI_MANAGED_NETWORK_CONFIG_DATA* mnp_config_data,
     EFI_SIMPLE_NETWORK_MODE* snp_mode_data) EFIAPI;

    EFI_STATUS(*Configure)
    (struct EFI_MANAGED_NETWORK_PROTOCOL* self,
     EFI_MANAGED_NETWORK_CONFIG_DATA* mnp_config_data) EFIAPI;

    EFI_STATUS(*McastIpToMac)
    (struct EFI_MANAGED_NETWORK_PROTOCOL* self, bool ipv6_flag, EFI_IP_ADDR* ip_addr,
     EFI_MAC_ADDR* mac_addr) EFIAPI;

    EFI_STATUS(*Groups)
    (struct EFI_MANAGED_NETWORK_PROTOCOL* self, bool join_flag, EFI_MAC_ADDR* mac_addr) EFIAPI;

    EFI_STATUS(*Transmit)
    (struct EFI_MANAGED_NETWORK_PROTOCOL* self,
     EFI_MANAGED_NETWORK_SYNC_COMPLETION_TOKEN* token) EFIAPI;

    EFI_STATUS(*Receive)
    (struct EFI_MANAGED_NETWORK_PROTOCOL* self,
     EFI_MANAGED_NETWORK_SYNC_COMPLETION_TOKEN* token) EFIAPI;

    EFI_STATUS(*Cancel)
    (struct EFI_MANAGED_NETWORK_PROTOCOL* self,
     EFI_MANAGED_NETWORK_SYNC_COMPLETION_TOKEN* token) EFIAPI;

    EFI_STATUS (*Poll)(struct EFI_MANAGED_NETWORK_PROTOCOL* self) EFIAPI;
} EFI_MANAGED_NETWORK_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_MANAGED_NETWORK_H_
