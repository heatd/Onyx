/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _ATA_H
#define _ATA_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <pci/pci.h>

/* STATUS */
#define ATA_SR_BSY              0x80 // Busy
#define ATA_SR_DRDY             0x40 // Drive ready
#define ATA_SR_DF               0x20 // Drive write fault
#define ATA_SR_DSC              0x10 // Drive seek complete
#define ATA_SR_DRQ              0x08 // Data request ready
#define ATA_SR_CORR             0x04 // Corrected data
#define ATA_SR_IDX              0x02 // Index
#define ATA_SR_ERR              0x01 // Error
/* ERRORS */
#define ATA_ER_BBK              0x80 // Bad sector
#define ATA_ER_UNC              0x40 // Uncorrectable data
#define ATA_ER_MC               0x20 // No media
#define ATA_ER_IDNF             0x10 // ID mark not found
#define ATA_ER_MCR              0x08 // No media
#define ATA_ER_ABRT             0x04 // Command aborted
#define ATA_ER_TK0NF            0x02 // Track 0 not found
#define ATA_ER_AMNF             0x01 // No address mark
/* COMMANDS */
#define ATA_CMD_READ_PIO        0x20
#define ATA_CMD_READ_PIO_EXT    0x24
#define ATA_CMD_READ_DMA        0xC8
#define ATA_CMD_READ_DMA_EXT    0x25
#define ATA_CMD_WRITE_PIO       0x30
#define ATA_CMD_WRITE_PIO_EXT   0x34
#define ATA_CMD_WRITE_DMA       0xCA
#define ATA_CMD_WRITE_DMA_EXT   0x35
#define ATA_CMD_CACHE_FLUSH     0xE7
#define ATA_CMD_CACHE_FLUSH_EXT 0xEA
#define ATA_CMD_PACKET          0xA0
#define ATA_CMD_IDENTIFY_PACKET 0xA1
#define ATA_CMD_IDENTIFY        0xEC
#define ATA_CMD_IDLE            0xE3
#define ATAPI_CMD_READ          0xA8
#define ATAPI_CMD_EJECT         0x1B
#define ATA_IDENT_DEVICETYPE    0
#define ATA_IDENT_CYLINDERS     2
#define ATA_IDENT_HEADS         6
#define ATA_IDENT_SECTORS       12
#define ATA_IDENT_SERIAL        20
#define ATA_IDENT_MODEL         54
#define ATA_IDENT_CAPABILITIES  98
#define ATA_IDENT_FIELDVALID    106
#define ATA_IDENT_MAX_LBA       120
#define ATA_IDENT_COMMANDSETS   164
#define ATA_IDENT_MAX_LBA_EXT   200

#define ATA_TYPE_ATA   1
#define ATA_TYPE_ATAPI 2

#endif
