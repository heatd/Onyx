/*
* Copyright (c) 2016-2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_IDE_H
#define _ONYX_IDE_H

#include <stdint.h>

typedef struct
{
	/* The buffer's address */
	uint32_t address;
	/* The buffer's size - 0 means 64KiB */
	uint16_t size;
	/* PRD's flags - only one flag is valid, the rest is reserved - see below */
	uint16_t flags;
} prdt_entry_t;

#define PRD_FLAG_END    (1 << 15)

#define ATA_REG_DATA       0x00
#define ATA_REG_ERROR      0x01
#define ATA_REG_FEATURES   0x01
#define ATA_REG_SECCOUNT0  0x02
#define ATA_REG_LBA0       0x03
#define ATA_REG_LBA1       0x04
#define ATA_REG_LBA2       0x05
#define ATA_REG_HDDEVSEL   0x06
#define ATA_REG_COMMAND    0x07
#define ATA_REG_STATUS     0x07

#define ATA_REG_CONTROL    0x0C
#define ATA_REG_ALTSTATUS  0x0

#define IDE_REG_DEVCTL     0

#define IDE_DEVCTL_NIEN    (1 << 0)
#define IDE_DEVCTL_SRST    (1 << 2)
#define IDE_DEVCTL_HOB     (1 << 7)

#define IDE_DATA1	       0x1F0
#define IDE_DATA2	   	   0x170
#define IDE_CONTROL1	   0x3F6
#define IDE_CONTROL2	   0x376

#define IDE_BMR_REG_COMMAND     0
#define IDE_BMR_REG_STATUS      2
#define IDE_BMR_REG_PRDT_ADDR   4

#define IDE_BMR_ST_DMA_MODE    (1 << 0)
#define IDE_BMR_ST_DMA_ERR     (1 << 1)
#define IDE_BMR_ST_IRQ_GEN     (1 << 2)
#define IDE_BMR_ST_SIMPLEX     (1 << 7)

#define IDE_BMR_CMD_START      (1 << 0)
#define IDE_BMR_CMD_WRITE      (1 << 3)

#define ATA_IRQ	  14

#endif
