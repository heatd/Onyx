/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _AHCI_H
#define _AHCI_H

#include <stdint.h>
#include <stdbool.h>

#include <onyx/spinlock.h>
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
	uint8_t padding[0x2C];
} cfis_t;

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
} fis_pio_setup_t;

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
} fis_dma_setup_t;

typedef struct
{
	cfis_t cfis;
	uint8_t acmd[16];
	uint8_t reserved[0x30];
} __attribute__((packed)) command_table_t;

typedef volatile struct
{
	uint16_t desc_info;
	uint16_t prdtl;
	uint32_t prdbc;
	uint32_t base_address_lo;
	uint32_t base_address_hi;
	uint32_t res[4];
} __attribute__((packed)) command_list_t;

typedef struct
{
	uint64_t address;
	uint32_t res0;
	uint32_t dw3;
} __attribute__((packed)) prdt_t;

#define AHCI_COMMAND_LIST_ATAPI		(1 << 5)
#define AHCI_COMMAND_LIST_WRITE		(1 << 6)
#define AHCI_COMMAND_LIST_PREFETCH	(1 << 7)
#define AHCI_COMMAND_LIST_RESET		(1 << 8)
#define AHCI_COMMAND_LIST_BIST		(1 << 9)
#define AHCI_COMMAND_LIST_CLEAR_BUSY	(1 << 10)

typedef volatile struct
{
	uint32_t command_list_base_low;
	uint32_t command_list_base_hi;
	uint32_t fis_list_base_low;
	uint32_t fis_list_base_hi;
	uint32_t interrupt_status;
	uint32_t pxie;

	uint32_t pxcmd;
	uint32_t resv0;
	uint32_t tfd;
	uint32_t sig;
	uint32_t status;
	uint32_t control;
	uint32_t error;
	uint32_t active;
	uint32_t command_issue;
	uint32_t sata_notification;
	uint32_t fbs;

	uint32_t resv1[11];
	uint32_t vendor[4];
} ahci_port_t;

typedef volatile struct
{
	uint32_t host_cap;
	uint32_t ghc;
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

struct command_list
{
	volatile bool recieved_interrupt;
	uint32_t last_interrupt_status;
};

struct ahci_port
{
	int port_nr;
	ahci_port_t *port;
	struct spinlock port_lock;
	command_table_t *ctable;
	prdt_t *prdt;
	struct command_list cmdslots[32];
	unsigned char identify[512];
};

struct ahci_device
{
	struct pci_device *pci_dev;
	ahci_hba_memory_regs_t *hba;
	struct ahci_port ports[32];
};

struct ahci_command_ata
{
	uint8_t cmd;
	size_t size;
	bool write;
	void *buffer;
	uint64_t lba;
};
/* Bitmasks for the capabilities register of the HBA */
#define AHCI_CAP_NR_PORTS(val)		(val & 0xF)
#define AHCI_CAP_SXS			(1 << 5)
#define AHCI_CAP_EMS			(1 << 6)
#define AHCI_CAP_CCCS			(1 << 7)
#define AHCI_CAP_NCS(val)		((val >> 8) & 0xF)
#define AHCI_CAP_PSC			(1 << 13)
#define AHCI_CAP_SSC			(1 << 14)
#define AHCI_CAP_PMD			(1 << 15)
#define AHCI_CAP_FBSS			(1 << 16)
#define AHCI_CAP_SPM			(1 << 17)
#define AHCI_CAP_AHCI_ONLY		(1 << 18)
#define AHCI_CAP_INTERFACE_SPEED(val)	((val >> 20) & 0xF)
#define AHCI_CAP_SCLO			(1 << 24)
#define AHCI_CAP_ACTIVITY_LED		(1 << 25)
#define AHCI_CAP_SALP			(1 << 26)
#define AHCI_CAP_STAGGERED_SPINUP	(1 << 27)
#define AHCI_CAP_SPMS			(1 << 28)
#define AHCI_CAP_SSNTF			(1 << 29)
#define AHCI_CAP_SNCQ			(1 << 30)
#define AHCI_CAP_ADDR64			(1L << 31)

#define AHCI_GHC_AHCI_ENABLE		(1L << 31)
#define AHCI_GHC_MRSM			(1 << 2)
#define AHCI_GHC_INTERRUPTS_ENABLE	(1 << 1)
#define AHCI_GHC_HBA_RESET		(1 << 0)

#define AHCI_PORT_CMD_START		(1 << 0)
#define AHCI_PORT_CMD_SPIN_UP_DEV	(1 << 1)
#define AHCI_PORT_CMD_POWER_ON_DEV	(1 << 2)
#define AHCI_PORT_CMD_CL_OVERRIDE	(1 << 3)
#define AHCI_PORT_CMD_FRE		(1 << 4)
#define AHCI_PORT_CMD_CURR_CMD_SLOT(val)	((val & 0xF00) >> 8)		
#define AHCI_PORT_CMD_MPSS		(1 << 13)
#define AHCI_PORT_CMD_FR		(1 << 14)
#define AHCI_PORT_CMD_CR		(1 << 15)
#define AHCI_PORT_CMD_CPS		(1 << 16)
#define AHCI_PORT_CMD_PMA		(1 << 17)
#define AHCI_PORT_CMD_HOTPLUG_PORT	(1 << 18)
#define AHCI_PORT_CMD_MPSP		(1 << 19)
#define AHCI_PORT_CMD_CPD		(1 << 20)
#define AHCI_PORT_CMD_ESP		(1 << 21)
#define AHCI_PORT_CMD_FBSCP		(1 << 22)
#define AHCI_PORT_CMD_APSTE		(1 << 23)
#define AHCI_PORT_CMD_ATAPI		(1 << 24)
#define AHCI_PORT_CMD_DLAE		(1 << 25)
#define AHCI_PORT_CMD_ALPE		(1 << 26)
#define AHCI_PORT_CMD_ASP		(1 << 27)
#define AHCI_PORT_CMD_ICC(val)		((val & F0000000) >> 28)

#define AHCI_PORT_STATUS_DET(val)	(val & 0xF)
#define AHCI_PORT_STATUS_SPD(val)	((val & 0xF0) >> 4)
#define AHCI_PORT_STATUS_IPM(val)	((val & 0xF00) >> 8)

#define AHCI_PORT_INTERRUPT_DHRE		(1 << 0)
#define AHCI_PORT_INTERRUPT_PSE			(1 << 1)
#define AHCI_PORT_INTERRUPT_DSE			(1 << 2)
#define AHCI_PORT_INTERRUPT_SDBE		(1 << 3)
#define AHCI_PORT_INTERRUPT_UFE			(1 << 4)
#define AHCI_PORT_INTERRUPT_DPE			(1 << 5)
#define AHCI_PORT_INTERRUPT_PCE			(1 << 6)
#define AHCI_PORT_INTERRUPT_DMPE		(1 << 7)
#define AHCI_PORT_INTERRUPT_PRCE		(1 << 22)
#define AHCI_PORT_INTERRUPT_IPME		(1 << 23)
#define AHCI_PORT_INTERRUPT_OFE			(1 << 24)
#define AHCI_PORT_INTERRUPT_INFE		(1 << 26)
#define AHCI_PORT_INTERRUPT_IFE			(1 << 27)
#define AHCI_PORT_INTERRUPT_HBDE		(1 << 28)
#define AHCI_PORT_INTERRUPT_HBFE		(1 << 29)
#define AHCI_PORT_INTERRUPT_TFEE		(1 << 30)
#define AHCI_PORT_INTERRUPT_CPDE		(1L << 31)

#define AHCI_INTST_ERROR	(AHCI_PORT_INTERRUPT_UFE | AHCI_PORT_INTERRUPT_PCE | \
AHCI_PORT_INTERRUPT_PRCE | AHCI_PORT_INTERRUPT_IPME | AHCI_PORT_INTERRUPT_OFE \
| AHCI_PORT_INTERRUPT_INFE | AHCI_PORT_INTERRUPT_IFE | AHCI_PORT_INTERRUPT_HBDE | \
AHCI_PORT_INTERRUPT_HBFE | AHCI_PORT_INTERRUPT_TFEE) 
uint32_t ahci_get_version(ahci_hba_memory_regs_t *hba);
char *ahci_stringify_version(uint32_t version);
#endif
