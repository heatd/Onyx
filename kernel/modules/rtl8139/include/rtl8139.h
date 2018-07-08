/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _RTL8139_H
#define _RTL8139_H

#include <onyx/spinlock.h>

#define RTL8139_DEVICEID 0x8139
#define RTL8139_VENDORID 0x10EC

#define RTL8139_PCI_MMIO_BAR	1
#define RTL8139_PCI_PIO_BAR	0	

#define RTL_NR_TX	4
/* RTL8139 registers according to http://realtek.info/pdf/rtl8139cp.pdf */
/* Note some of them are omitted since we don't use them all */
#define REG_MAC		0x00
#define REG_MAR		0x08
#define REG_TSD0	0x10
#define REG_TSD1	0x14
#define REG_TSD2	0x18
#define REG_TSD3	0x1C
#define REG_TSAD0	0x20
#define REG_TSAD1	0x24
#define REG_TSAD2	0x28
#define REG_TSAD3	0x2C
#define REG_RBSTART	0x30
#define REG_ERBCR	0x34
#define REG_ERSR	0x36
#define REG_CMD		0x37
#define REG_CAPR	0x38
#define REG_CBR		0x3A
#define REG_IMR		0x3C
#define REG_ISR		0x3E
#define REG_TCR		0x40
#define REG_RCR		0x44
#define REG_TCTR	0x48
#define REG_MPC		0x4C
#define REG_9346CR	0x50
#define REG_CONFIG0	0x51
#define REG_CONFIG1	0x52
#define REG_TIMERINT	0x54
#define REG_MSR		0x58
#define REG_CONFIG3	0x59
#define REG_CONFIG4	0x5A
#define REG_MULINT	0x5C
#define REG_RERID	0x5E
#define REG_TSAD	0x60

#define ISR_ROK			(1 << 0)
#define ISR_RER			(1 << 1)
#define ISR_TOK			(1 << 2)
#define ISR_TER			(1 << 3)

#define IMR_ROK			(1 << 0)
#define IMR_RER			(1 << 1)
#define IMR_TOK			(1 << 2)
#define IMR_TER			(1 << 3)
#define IMR_RBO			(1 << 4)
#define IMR_PUN			(1 << 5)
#define IMR_FOVW		(1 << 6)
#define IMR_TDU			(1 << 7)
#define IMR_SWINT		(1 << 8)
#define IMR_LENCHG		(1 << 13)
#define IMR_TIMEOUT		(1 << 14)
#define IMR_SERR		(1 << 15)

#define RCR_AAP			(1 << 0)
#define RCR_APM			(1 << 1)
#define RCR_AM 			(1 << 2)
#define RCR_AB			(1 << 3)
#define RCR_WRAP		(1 << 7)

#define CMD_BUFFER_EMPTY	(1 << 0)
#define CMD_TRANSMITTER_ENABLE	(1 << 2)
#define CMD_RECIEVER_ENABLE	(1 << 3)
#define CMD_RESET		(1 << 4)

#define TSD_OWN			(1 << 13)
#define TSD_TUN			(1 << 14)
#define TSD_TOK			(1 << 15)

struct tx_buffer
{
	void *buffer;
	struct spinlock lock;
};
#endif
