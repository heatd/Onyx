/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _RTL8168_H
#define _RTL8168_H

// The ID registers (0 through 5) contain the MAC address of the NIC
#define RTL8168_IDR0     0x0
#define RTL8168_IDRx(x)  (RTL8168_IDR0 + x)

// Multicast address register - these registers go downwards
#define RTL8168_MAR7     0x8
#define RTL8168_MARx(x)  ((0x8 + 7) - x)

// Dump tally command register - for stats
#define RTL8168_DTCCR    0x10

// Note that the TX descriptor start addresses need to be 256-byte aligned
// Holds the start address of the TX descriptors for normal priority
#define RTL8168_TNPDS    0x20

// Start address for high priority
#define RTL8168_THPDS    0x28

// Command register
#define RTL8168_CR       0x37

// Interrupt mask register
#define RTL8168_IMR      0x3c

// Interrupt status register
#define RTL8118_ISR      0x3e


// TX configuration register
#define RTL8168_TCR      0x40

// RX configuration register
#define RTL8168_RCR      0x44

// C+ command register
#define RTL8168_CPLUS    0xe0
#endif
