/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _DRIVERS_E1000_H
#define _DRIVERS_E1000_H

#include <stdint.h>
#include <pci/pci.h>

#define INTEL_VENDOR		0x8086 
#define E1000_DEV			0x100E
#define E1000_I217			0x153A
#define E1000E_DEV			0x10D3
#define E1000_82577LM		0x10EA
 
/* Register values look up in linux/drivers/net/ethernet/intel/e1000e/regs.h */
#define REG_CTRL		0x0000
#define REG_STATUS		0x0008
#define REG_EECD		0x0010
#define REG_EEPROM		0x0014
#define REG_CTRL_EXT	0x0018
#define REG_FLA			0x001c
#define REG_MDIC		0x0020
#define REG_SCTL		0x0024
#define REG_FCAL		0x0028
#define REG_FCAH		0x002c
#define REG_FEXT		0x002c
#define REG_FCT			0x0030
#define REG_ICR			0x00c0
#define REG_IMS			0x00d0
#define REG_IMC			0x00d8
#define REG_IVAR		0x00e4
#define REG_RCTL		0x0100
#define REG_FCTTV		0x0170
#define REG_RXDESCLO		0x2800
#define REG_RXDESCHI		0x2804
#define REG_RXDESCLEN		0x2808
#define REG_RXDESCHEAD		0x2810
#define REG_RXDESCTAIL		0x2818
#define REG_CRCERRS		0x4000
#define REG_TCTL		0x0400
#define REG_TXDESCLO		0x3800
#define REG_TXDESCHI		0x3804
#define REG_TXDESCLEN		0x3808
#define REG_TXDESCHEAD		0x3810
#define REG_TXDESCTAIL		0x3818


#define REG_RDTR		0x2820 // RX Delay Timer Register
#define REG_RXDCTL		0x3828 // RX Descriptor Control
#define REG_RADV		0x282C // RX Int. Absolute Delay Timer
#define REG_RSRPD		0x2C00 // RX Small Packet Detect Interrupt


#define REG_TIPG		0x0410 /* Transmit Inter Packet Gap */

#define RCTL_EN				(1 << 1)    // Receiver Enable
#define RCTL_SBP			(1 << 2)    // Store Bad Packets
#define RCTL_UPE			(1 << 3)    // Unicast Promiscuous Enabled
#define RCTL_MPE			(1 << 4)    // Multicast Promiscuous Enabled
#define RCTL_LPE			(1 << 5)    // Long Packet Reception Enable
#define RCTL_LBM_NONE			(0 << 6)    // No Loopback
#define RCTL_LBM_PHY			(3 << 6)    // PHY or external SerDesc loopback
#define RTCL_RDMTS_HALF			(0 << 8)    // Free Buffer Threshold is 1/2 of RDLEN
#define RTCL_RDMTS_QUARTER		(1 << 8)    // Free Buffer Threshold is 1/4 of RDLEN
#define RTCL_RDMTS_EIGHTH		(2 << 8)    // Free Buffer Threshold is 1/8 of RDLEN
#define RCTL_MO_36			(0 << 12)   // Multicast Offset - bits 47:36
#define RCTL_MO_35			(1 << 12)   // Multicast Offset - bits 46:35
#define RCTL_MO_34			(2 << 12)   // Multicast Offset - bits 45:34
#define RCTL_MO_32			(3 << 12)   // Multicast Offset - bits 43:32
#define RCTL_BAM			(1 << 15)   // Broadcast Accept Mode
#define RCTL_VFE			(1 << 18)   // VLAN Filter Enable
#define RCTL_CFIEN			(1 << 19)   // Canonical Form Indicator Enable
#define RCTL_CFI			(1 << 20)   // Canonical Form Indicator Bit Value
#define RCTL_DPF			(1 << 22)   // Discard Pause Frames
#define RCTL_PMCF			(1 << 23)   // Pass MAC Control Frames
#define RCTL_SECRC			(1 << 26)   // Strip Ethernet CRC

#define RCTL_BSIZE_256			(3 << 16)
#define RCTL_BSIZE_512			(2 << 16)
#define RCTL_BSIZE_1024			(1 << 16)
#define RCTL_BSIZE_2048			(0 << 16)
#define RCTL_BSIZE_4096			((3 << 16) | (1 << 25))
#define RCTL_BSIZE_8192			((2 << 16) | (1 << 25))
#define RCTL_BSIZE_16384		((1 << 16) | (1 << 25))


// Transmit Command
 
#define CMD_EOP				(1 << 0)    // End of Packet
#define CMD_IFCS			(1 << 1)    // Insert FCS
#define CMD_IC				(1 << 2)    // Insert Checksum
#define CMD_RS				(1 << 3)    // Report Status
#define CMD_RPS				(1 << 4)    // Report Packet Sent
#define CMD_VLE				(1 << 6)    // VLAN Packet Enable
#define CMD_IDE				(1 << 7)    // Interrupt Delay Enable
 
 
// TCTL Register
 
#define TCTL_EN				(1 << 1)    // Transmit Enable
#define TCTL_PSP			(1 << 3)    // Pad Short Packets
#define TCTL_CT_SHIFT			4           // Collision Threshold
#define TCTL_COLD_SHIFT			12          // Collision Distance
#define TCTL_SWXOFF			(1 << 22)   // Software XOFF Transmission
#define TCTL_RTLC			(1 << 24)   // Re-transmit on Late Collision
#define TCTL_RRTHRESH(x)	(x << 29)

#define TSTA_DD				(1 << 0)    // Descriptor Done
#define TSTA_EC				(1 << 1)    // Excess Collisions
#define TSTA_LC				(1 << 2)    // Late Collision
#define LSTA_TU				(1 << 3)    // Transmit Underrun

#define POPTS_IXSM			(1 << 0)
#define POPTS_TXSM			(1 << 1)

#define MAX_MTU 			1514

/* CTRL Register */
#define CTRL_FD					(1 << 0)
#define CTRL_GIO_MASTER_DIS		(1 << 1)
#define CTRL_ASDE				(1 << 5)
#define CTRL_SLU				(1 << 6)
#define CTRL_SPEED_10MB			(0)
#define CTRL_SPEED_100MB		(1 << 8)
#define CTRL_SPEED_1000MB		(2 << 8)
#define CTRL_FORCE_SPEED		(1 << 11)
#define CTRL_FRCDPLX			(1 << 12)
#define CTRL_ADVD3WUC			(1 << 20)
#define CTRL_RST				(1 << 26)
#define CTRL_RFCE				(1 << 27)
#define CTRL_TFCE				(1 << 28)
#define CTRL_VME				(1 << 30)
#define CTRL_PHY_RST			(1U << 31)

#define ICR_TXDW		(1 << 0)
#define ICR_TXQE		(1 << 1)
#define ICR_LSC			(1 << 2)
#define ICR_RXDMT0		(1 << 4)
#define ICR_DSW			(1 << 5)
#define ICR_RXO			(1 << 6)
#define ICR_RXT0		(1 << 7)
#define ICR_MDAC		(1 << 9)
#define ICR_PHYINT		(1 << 12)
#define ICR_LSECPN		(1 << 14)
#define ICR_TXDLOW		(1 << 15)
#define ICR_SRPD		(1 << 16)
#define ICR_ACK			(1 << 17)
#define ICR_MNG			(1 << 18)
#define ICR_EPRST		(1 << 20)
#define ICR_ECCER		(1 << 22)
#define ICR_INT_ASSERTED	(1 << 31)

#define IMS_TXDW		(1 << 0)
#define IMS_TXQE		(1 << 1)
#define IMS_RXT0		(1 << 7)

struct e1000_rx_desc
{
	volatile uint64_t addr;
	volatile uint16_t length;
	volatile uint16_t checksum;
	volatile uint8_t status;
	volatile uint8_t errors;
	volatile uint16_t special;
} __attribute__((packed));
 
struct e1000_tx_desc
{
	volatile uint64_t addr;
	volatile uint16_t length;
	volatile uint8_t cso;
	volatile uint8_t cmd;
	volatile uint8_t status;
	volatile uint8_t popts;
	volatile uint16_t special;
} __attribute__((packed));

#endif
