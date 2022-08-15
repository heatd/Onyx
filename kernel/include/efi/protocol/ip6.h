// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_IP6_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_IP6_H_

#include <stdbool.h>

#include <onyx/compiler.h>

#include <efi/types.h>

__BEGIN_CDECLS

typedef struct
{
    uint8_t DefaultProtocol;
    bool AcceptAnyProtocol;
    bool AcceptIcmpErrors;
    bool AcceptPromiscuous;
    EFI_IPV6_ADDR DestinationAddress;
    EFI_IPV6_ADDR StationAddress;
    uint8_t TrafficClass;
    uint8_t HopLimit;
    uint32_t FlowLabel;
    uint32_t ReceiveTimeout;
    uint32_t TransmitTimeout;
} EFI_IP6_CONFIG_DATA;

typedef struct
{
    EFI_IPV6_ADDR Address;
    uint8_t PrefixLength;
} EFI_IP6_ADDRESS_INFO;

typedef struct
{
    EFI_IPV6_ADDR Gateway;
    EFI_IPV6_ADDR Destination;
    uint8_t PrefixLength;
} EFI_IP6_ROUTE_TABLE;

typedef enum
{
    EfiNeighborInComplete,
    EfiNeighborReachable,
    EfiNeighborStale,
    EfiNeighborDelay,
    EfiNeighborProbe
} EFI_IP6_NEIGHBOR_STATE;

typedef struct
{
    EFI_IPV6_ADDR Neighbor;
    EFI_MAC_ADDR LinkAddress;
    EFI_IP6_NEIGHBOR_STATE State;
} EFI_IP6_NEIGHBOR_CACHE;

typedef struct
{
    uint8_t Type;
    uint8_t Code;
} EFI_IP6_ICMP_TYPE;

typedef struct
{
    bool IsStarted;
    uint32_t MaxPacketSize;
    EFI_IP6_CONFIG_DATA ConfigData;
    bool IsConfigured;
    uint32_t AddressCount;
    EFI_IP6_ADDRESS_INFO* AddressList;
    uint32_t GroupCount;
    EFI_IPV6_ADDR* GroupTable;
    uint32_t RouteCount;
    EFI_IP6_ROUTE_TABLE* RouteTable;
    uint32_t NeighborCount;
    EFI_IP6_NEIGHBOR_CACHE* NeighborCache;
    uint32_t PrefixCount;
    EFI_IP6_ADDRESS_INFO* PrefixTable;
    uint32_t IcmpTypeCount;
    EFI_IP6_ICMP_TYPE* IcmpTypeList;
} EFI_IP6_MODE_DATA;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_IP6_H_
