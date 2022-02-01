/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_PCI_MSI_H
#define _ONYX_PCI_MSI_H
#include <stdint.h>

#define PCI_MSI_MESSAGE_CONTROL_OFF		2
#define PCI_MSI_MESSAGE_ADDRESS_OFF		4

#define PCI_MSI_MSGCTRL_ENABLE		(1 << 0)
#define PCI_MSI_MSGCTRL_MMC(ctrl)	((ctrl >> 1) & 0x7)
#define PCI_MSI_MSGCTRL_MME(ctrl)	((ctrl >> 4) & 0x7)
#define PCI_MSI_MSGCTRL_64BIT		(1 << 7)
#define PCI_MSI_MSGCTRL_PERVECTOR_MSK	(1 << 8)

#define PCI_MSI_1_VECTOR		0x0000
#define PCI_MSI_2_VECTORS		0x0001
#define PCI_MSI_4_VECTORS		0x0002
#define PCI_MSI_8_VECTORS		0x0003
#define PCI_MSI_16_VECTORS		0x0004
#define PCI_MSI_32_VECTORS		0x0005

struct pci_msi_data
{
	uint32_t address;
	uint32_t address_high;
	uint32_t data;
	uint32_t vector_start;
	uint32_t irq_offset; // Note: This is hacky and should be replaced by something like IRQ domains or something
};

#endif
