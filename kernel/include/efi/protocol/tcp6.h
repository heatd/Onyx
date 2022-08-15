// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_TCP6_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_TCP6_H_

#include <stdbool.h>

#include <onyx/compiler.h>

#include <efi/protocol/ip6.h>
#include <efi/protocol/managed-network.h>
#include <efi/protocol/simple-network.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_TCP6_SERVICE_BINDING_PROTOCOL_GUID             \
    {                                                      \
        0xec20eb79, 0x6c1a, 0x4664,                        \
        {                                                  \
            0x9a, 0x0d, 0xd2, 0xe4, 0xcc, 0x16, 0xd6, 0x64 \
        }                                                  \
    }

#define EFI_TCP6_PROTOCOL_GUID                             \
    {                                                      \
        0x46e44855, 0xbd60, 0x4ab7,                        \
        {                                                  \
            0xab, 0x0d, 0xa6, 0x79, 0xb9, 0x44, 0x7d, 0x77 \
        }                                                  \
    }

typedef struct
{
    EFI_IPV6_ADDR StationAddress;
    uint16_t StationPort;
    EFI_IPV6_ADDR RemoteAddress;
    uint16_t RemotePort;
    bool ActiveFlag;
} EFI_TCP6_ACCESS_POINT;

typedef struct
{
    uint32_t ReceiveBufferSize;
    uint32_t SendBufferSize;
    uint32_t MaxSynBackLog;
    uint32_t ConnectionTimeout;
    uint32_t DataRetries;
    uint32_t FinTimeout;
    uint32_t TimeWaitTimeout;
    uint32_t KeepAliveProbes;
    uint32_t KeepAliveTime;
    uint32_t KeepAliveInterval;
    bool EnableNagle;
    bool EnableTimeStamp;
    bool EnableWindowScaling;
    bool EnableSelectiveAck;
    bool EnablePathMtuDiscovery;
} EFI_TCP6_OPTION;

typedef struct
{
    uint8_t TrafficClass;
    uint8_t HopLimit;
    EFI_TCP6_ACCESS_POINT AccessPoint;
    EFI_TCP6_OPTION* ControlOption;
} EFI_TCP6_CONFIG_DATA;

typedef enum
{
    Tcp6StateClosed = 0,
    Tcp6StateListen = 1,
    Tcp6StateSynSent = 2,
    Tcp6StateSynReceived = 3,
    Tcp6StateEstablished = 4,
    Tcp6StateFinWait1 = 5,
    Tcp6StateFinWait2 = 6,
    Tcp6StateClosing = 7,
    Tcp6StateTimeWait = 8,
    Tcp6StateCloseWait = 9,
    Tcp6StateLastAck = 10
} EFI_TCP6_CONNECTION_STATE;

typedef struct
{
    EFI_EVENT Event;
    EFI_STATUS Status;
} EFI_TCP6_COMPLETION_TOKEN;

typedef struct
{
    EFI_TCP6_COMPLETION_TOKEN CompletionToken;
} EFI_TCP6_CONNECTION_TOKEN;

typedef struct
{
    EFI_TCP6_COMPLETION_TOKEN CompletionToken;
    EFI_HANDLE NewChildHandle;
} EFI_TCP6_LISTEN_TOKEN;

typedef struct
{
    uint32_t FragmentLength;
    void* FragmentBuffer;
} EFI_TCP6_FRAGMENT_DATA;

typedef struct
{
    bool UrgentFlag;
    uint32_t DataLength;
    uint32_t FragmentCount;
    EFI_TCP6_FRAGMENT_DATA FragmentTable[1];
} EFI_TCP6_RECEIVE_DATA;

typedef struct
{
    bool Push;
    bool Urgent;
    uint32_t DataLength;
    uint32_t FragmentCount;
    EFI_TCP6_FRAGMENT_DATA FragmentTable[1];
} EFI_TCP6_TRANSMIT_DATA;

typedef struct
{
    EFI_TCP6_COMPLETION_TOKEN CompletionToken;
    union {
        EFI_TCP6_RECEIVE_DATA* RxData;
        EFI_TCP6_TRANSMIT_DATA* TxData;
    } Packet;
} EFI_TCP6_IO_TOKEN;

typedef struct
{
    EFI_TCP6_COMPLETION_TOKEN CompletionToken;
    bool AbortOnClose;
} EFI_TCP6_CLOSE_TOKEN;

typedef struct EFI_TCP6_PROTOCOL
{
    EFI_STATUS(*GetModeData)
    (struct EFI_TCP6_PROTOCOL* self, EFI_TCP6_CONNECTION_STATE* tcp6_state,
     EFI_TCP6_CONFIG_DATA* tcp6_config_data, EFI_IP6_MODE_DATA* ip6_mode_data,
     EFI_MANAGED_NETWORK_CONFIG_DATA* mnp_config_data,
     EFI_SIMPLE_NETWORK_MODE* snp_mode_data) EFIAPI;

    EFI_STATUS(*Configure)
    (struct EFI_TCP6_PROTOCOL* self, EFI_TCP6_CONFIG_DATA* tcp6_config_data) EFIAPI;

    EFI_STATUS(*Connect)
    (struct EFI_TCP6_PROTOCOL* self, EFI_TCP6_CONNECTION_TOKEN* connection_token) EFIAPI;

    EFI_STATUS(*Accept)
    (struct EFI_TCP6_PROTOCOL* self, EFI_TCP6_LISTEN_TOKEN* listen_token) EFIAPI;

    EFI_STATUS (*Transmit)(struct EFI_TCP6_PROTOCOL* self, EFI_TCP6_IO_TOKEN* token) EFIAPI;

    EFI_STATUS (*Receive)(struct EFI_TCP6_PROTOCOL* self, EFI_TCP6_IO_TOKEN* token) EFIAPI;

    EFI_STATUS (*Close)(struct EFI_TCP6_PROTOCOL* self, EFI_TCP6_CLOSE_TOKEN* close_token) EFIAPI;

    EFI_STATUS (*Cancel)(struct EFI_TCP6_PROTOCOL* self, EFI_TCP6_COMPLETION_TOKEN* token) EFIAPI;

    EFI_STATUS (*Poll)(struct EFI_TCP6_PROTOCOL* self) EFIAPI;
} EFI_TCP6_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_TCP6_H_
