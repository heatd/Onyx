/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _VMWARE_SVGAII_H
#define _VMWARE_SVGAII_H

#define VMWARE_SVGAII_PCI_VENDOR 0x15AD
#define VMWARE_SVGAII_PCI_DEVICE 0x0405

#define SVGAII_IO_SPACE_BAR		0
#define SVGAII_FRAMEBUFFER_BAR		1
#define SVGAII_COMMAND_BUFFER_BAR	2

#define SVGA_INDEX_PORT         0x0
#define SVGA_VALUE_PORT         0x1
#define SVGA_BIOS_PORT          0x2
#define SVGA_IRQSTATUS_PORT     0x8

#define SVGA_REG_ID		0
#define SVGA_REG_ENABLE		1
#define SVGA_REG_WIDTH		2
#define SVGA_REG_HEIGHT		3
#define SVGA_REG_MAX_WIDTH	4
#define SVGA_REG_MAX_HEIGHT	5
#define SVGA_REG_DEPTH		6
#define SVGA_REG_BITS_PER_PIXEL	7
#define SVGA_REG_PSEUDOCOLOR 	8
#define SVGA_REG_RED_MASK 	9
#define SVGA_REG_GREEN_MASK 	10
#define SVGA_REG_BLUE_MASK 	11
#define SVGA_REG_BYTES_PER_LINE 12
#define SVGA_REG_FB_START 	13          /* (Deprecated) */
#define SVGA_REG_FB_OFFSET 	14
#define SVGA_REG_VRAM_SIZE 	15
#define SVGA_REG_FB_SIZE 	16
#endif