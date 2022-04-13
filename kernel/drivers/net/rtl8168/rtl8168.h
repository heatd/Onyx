/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _RTL8168_H
#define _RTL8168_H

#include <stdint.h>

// The ID registers (0 through 5) contain the MAC address of the NIC
#define RTL8168_IDR0    0x0
#define RTL8168_IDRx(x) (RTL8168_IDR0 + x)

// Multicast address register - these registers go downwards
#define RTL8168_MAR7    0x8
#define RTL8168_MARx(x) ((0x8 + 7) - x)

// Dump tally command register - for stats
#define RTL8168_DTCCR 0x10

// Note that the TX descriptor start addresses need to be 256-byte aligned
// Holds the start address of the TX descriptors for normal priority
#define RTL8168_TNPDS_LOW  0x20
#define RTL8168_TNPDS_HIGH 0x24

// Start address for high priority
#define RTL8168_THPDS 0x28

// Command register
#define RTL8168_CR 0x37

// Transmit priority polling
#define RTL8168_TPPOLL 0x38

#define RTL8168_TPPOLL_NPQ (1 << 6)

// Interrupt mask register
#define RTL8168_IMR 0x3c

// Interrupt status register
#define RTL8118_ISR 0x3e

// TX configuration register
#define RTL8168_TCR 0x40

// RX configuration register
#define RTL8168_RCR 0x44

// 9436CR register
#define RTL8168_9436CR 0x50

// RX max packet size
#define RTL8168_RMS 0xda

// C+ command register
#define RTL8168_CPLUS 0xe0

// Receive descriptor start address
// 64-bit but accessed in 32-bit halves
#define RTL8168_RDSAR_LOW  0xe4
#define RTL8168_RDSAR_HIGH 0xe8

// Max transmit packet size, in 128 byte units
#define RTL8168_MTPS 0xec

#define RTL8168_CPLUS_RXCHKSUM       (1 << 5)
#define RTL8168_CPLUS_VLAN_DETAGGING (1 << 6)

#define RTL8168_CR_TX_ENABLE (1 << 2)
#define RTL8168_CR_RX_ENABLE (1 << 3)
#define RTL8168_CR_RST       (1 << 4)

// As a refresher
// AAP = accept all packets
// APM = accept physical match packets (packets with the same MAC?)
// AM = accept multicast packets
// AB = accept broadcast packets
// AR = accept runt
// AER = accept error packet

#define RTL8168_RXCFG_AAP             (1 << 0)
#define RTL8168_RXCFG_APM             (1 << 1)
#define RTL8168_RXCFG_AM              (1 << 2)
#define RTL8168_RXCFG_AB              (1 << 3)
#define RTL8168_RXCFG_AR              (1 << 4)
#define RTL8168_RXCFG_AER             (1 << 5)
#define RTL8168_RXCFG_9356SEL         (1 << 6)
#define RTL8168_RXCFG_MXDMA_UNLIMITED (0b111 << 8)
#define RTL8168_RXCFG_NO_RX_THRESHOLD (0b111 << 13)

#define RTL8168_TXCFG_IFG96           (0b011 << 24)
#define RTL8168_TXCFG_NOCRC           (1 << 16)
#define RTL8168_TXCFG_MXDMA_UNLIMITED (0b111 << 8)

#define RTL8168_9436CR_EEM_MASK   (3 << 6)
#define RTL8168_9436CR_EEM_LOCK   (0 << 6)
#define RTL8168_9436CR_EEM_UNLOCK (3 << 6)

#define RTL8168_RX_DESC_FLAG_TCPF (1 << 14)
#define RTL8168_RX_DESC_FLAG_UDPF (1 << 15)
#define RTL8168_RX_DESC_FLAG_IPF  (1 << 16)
#define RTL8168_RX_DESC_FLAG_PID1 (1 << 17)
#define RTL8168_RX_DESC_FLAG_PID2 (1 << 18)
#define RTL8168_RX_DESC_FLAG_CRC  (1 << 19)
#define RTL8168_RX_DESC_FLAG_RUNT (1 << 20)
#define RTL8168_RX_DESC_FLAG_RES  (1 << 21)
#define RTL8168_RX_DESC_FLAG_RWT  (1 << 22)
#define RTL8168_RX_DESC_FLAG_BAR  (1 << 25)
#define RTL8168_RX_DESC_FLAG_PAM  (1 << 26)
#define RTL8168_RX_DESC_FLAG_MAR  (1 << 27)
#define RTL8168_RX_DESC_FLAG_LS   (1 << 28)
#define RTL8168_RX_DESC_FLAG_FS   (1 << 29)
#define RTL8168_RX_DESC_FLAG_EOR  (1 << 30)
#define RTL8168_RX_DESC_FLAG_OWN  (1 << 31)

#define RTL8168_RX_LENGTH_MASK ((1 << 14) - 1)
struct rtl8168_rx_desc
{
    uint32_t status;
    uint32_t vlan;
    uint32_t buffer_addr_low;
    uint32_t buffer_addr_high;
};

#define RTL8168_TX_DESC_FLAG_TCPCS (1 << 16)
#define RTL8168_TX_DESC_FLAG_UDPCS (1 << 17)
#define RTL8168_TX_DESC_FLAG_IPCS  (1 << 18)
#define RTL8168_TX_DESC_FLAG_LGSEN (1 << 27)
#define RTL8168_TX_DESC_FLAG_LS    (1 << 28)
#define RTL8168_TX_DESC_FLAG_FS    (1 << 29)
#define RTL8168_TX_DESC_FLAG_EOR   (1 << 30)
#define RTL8168_TX_DESC_FLAG_OWN   (1 << 31)

struct rtl8168_tx_desc
{
    uint32_t status;
    uint32_t vlan;
    uint32_t buffer_addr_low;
    uint32_t buffer_addr_high;
};

#define RTL8168_INT_MASK    ((1 << 14) | 0x3ff)
#define RTL8168_INT_LINKCHG (1 << 5)
#define RTL8168_INT_TOK     (1 << 2)
#define RTL8168_INT_ROK     (1 << 0)

// Interrupt status register
#define RTL8168_ISR 0x3e

#define RTL8168_PHYSTATUS         0x6c
#define RTL8168_PHYSTATUS_LINKSTS (1 << 1)
#endif
