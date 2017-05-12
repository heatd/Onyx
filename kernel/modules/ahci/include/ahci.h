/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _AHCI_H
#define _AHCI_H

#define	SATA_SIG_ATA	0x00000101	// SATA drive
#define	SATA_SIG_ATAPI	0xEB140101	// SATAPI drive

typedef enum
{
	FIS_TYPE_REG_H2D	= 0x27,	// Register FIS - host to device
	FIS_TYPE_REG_D2H	= 0x34,	// Register FIS - device to host
	FIS_TYPE_DMA_ACT	= 0x39,	// DMA activate FIS - device to host
	FIS_TYPE_DMA_SETUP	= 0x41,	// DMA setup FIS - bidirectional
	FIS_TYPE_DATA		= 0x46,	// Data FIS - bidirectional
	FIS_TYPE_BIST		= 0x58,	// BIST activate FIS - bidirectional
	FIS_TYPE_PIO_SETUP	= 0x5F,	// PIO setup FIS - device to host
	FIS_TYPE_DEV_BITS	= 0xA1,	// Set device bits FIS - device to host
} FIS_TYPE;

typedef struct
{
	uint8_t fis_type; 	// FIS Type

	uint8_t port_mult : 4; 	// Port multiplier
	uint8_t resv0 : 3;	// Reserved - should be zero
	uint8_t c : 1;		// 1 - Command, 0 - Control
	
	uint8_t command;	// Command register
	uint8_t feature_low;	// Feature register low

	uint8_t lba0, lba1, lba2;
	uint8_t device;		// Device register

	uint8_t lba3, lba4, lba5;
	uint8_t feature_high;	// Feature register high

	uint16_t count;		// Count
	uint8_t icc;
	uint8_t control;

	uint32_t resv1;
} fis_reg_h2d;

typedef struct
{
	uint8_t fis_type; 	// FIS Type

	uint8_t port_mult : 4; 	// Port multiplier
	uint8_t resv0 : 2;	// Reserved - should be zero
	uint8_t intr : 1;	// Interrupt bit
	uint8_t resv1 : 1;

	uint8_t status;	// Status register
	uint8_t error;	// Error register

	uint8_t lba0, lba1, lba2;
	uint8_t device;		// Device register

	uint8_t lba3, lba4, lba5;
	uint8_t resv2;

	uint16_t count;		// Count
	uint8_t icc;
	uint16_t resv3;

	uint32_t resv4;
} fis_reg_d2h;

typedef struct
{
	uint8_t fis_type;

	uint8_t port_mult : 4;
	uint8_t resv0 : 4;

	uint16_t resv1;

	unsigned char data[0];
} fis_data;

typedef struct
{
	uint8_t fis_type;

	uint8_t port_mult : 4;
	uint8_t resv0 : 1;
	uint8_t direction : 1;
	uint8_t interrupt : 1;
	uint8_t resv1 : 1;

	uint8_t status, error;

	uint8_t lba0, lba1, lba2;
	uint8_t resv2;

	uint16_t count;
	uint8_t resv3;
	uint8_t new_status;

	uint16_t transfer_count;
	uint32_t resv4; 
} fis_pio_setup;

typedef struct
{
	uint8_t fis_type;

	uint8_t port_mult : 4;
	uint8_t resv0 : 1;
	uint8_t direction : 1;
	uint8_t interrupt : 1;
	uint8_t auto_activate : 1;

	uint16_t resv1;

	uint64_t dma_buffer_id;

	uint32_t resv2;

	uint32_t dma_buffer_off;
	uint32_t tranfer_count;
	uint32_t resv3;
} fis_dma_setup;

typedef volatile struct
{
	uint64_t command_list_base;
	uint64_t fis_list_base;
	uint32_t interrupt_status;
	uint32_t interrupt_enable;

	uint32_t cmd;
	uint32_t resv0;
	uint32_t tfd;
	uint32_t sig;
	uint32_t sata_status;
	uint32_t sata_control;
	uint32_t sata_error;
	uint32_t sata_active;
	uint32_t command_issue;
	uint32_t sata_notification;
	uint32_t fbs;

	uint32_t resv1[11];
	uint32_t vendor[4];
} ahci_port_t;
typedef volatile struct
{
	uint32_t host_cap;
	uint32_t global_host_ctl;
	uint32_t interrupt_status;
	uint32_t ports_implemented;
	uint32_t version;
	uint32_t ccc_ctl;
	uint32_t ccc_ports;
	uint32_t em_loc;
	uint32_t em_ctl;
	uint32_t host_cap2;
	uint32_t bohc;

	uint8_t	resv[0xA0-0x2C];
 
	// Vendor specific registers
	uint8_t	vendor[0x100-0xA0];
	
	ahci_port_t ports[32];
} ahci_hba_memory_regs_t;
#endif