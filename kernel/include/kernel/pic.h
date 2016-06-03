/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _PIC_H
#define _PIC_H
#include <stdint.h>
#define PIC1		0x20		/* IO base address for master PIC */
#define PIC2		0xA0		/* IO base address for slave PIC */
#define PIC1_COMMAND	PIC1
#define PIC1_DATA	(PIC1+1)
#define PIC2_COMMAND	PIC2
#define PIC2_DATA	(PIC2+1)
#define PIC_READ_IRR	0x0a
#define PIC_READ_ISR	0x0b
#define PIC_EOI		0x20		/* End-of-interrupt command code */
namespace PIC
{
void Disable();
void Remap();
void UnmaskIRQ(uint16_t irqn);
void MaskIRQ(uint16_t irqn);
void SendEOI(unsigned char irqn);
uint16_t GetIRR();
uint16_t GetISR();
}
#endif
