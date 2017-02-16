/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _DRIVERS_BOCHSVGA_H
#define _DRIVERS_BOCHSVGA_H
#include <stdint.h>
#include <stddef.h>
#include <drivers/pci.h>

/* Bochs VGA I/O ports */
#define VBE_DISPI_IOPORT_INDEX		0x01CE
#define VBE_DISPI_IOPORT_DATA		0x01CF
/* Bochs VGA index registers */
#define VBE_DISPI_INDEX_ID 		0
#define VBE_DISPI_INDEX_XRES 		1
#define VBE_DISPI_INDEX_YRES 		2
#define VBE_DISPI_INDEX_BPP 		3
#define VBE_DISPI_INDEX_ENABLE 		4
#define VBE_DISPI_INDEX_BANK 		5
#define VBE_DISPI_INDEX_VIRT_WIDTH 	6
#define VBE_DISPI_INDEX_VIRT_HEIGHT 	7
#define VBE_DISPI_INDEX_X_OFFSET 	8
#define VBE_DISPI_INDEX_Y_OFFSET 	9

#define BOCHSVGA_PCI_DEVICEID 0x1234
#define BOCHSVGA_PCI_VENDORID 0x1111
void bochsvga_init(PCIDevice *dev);

#endif