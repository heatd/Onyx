/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_X86_PIC_H
#define _ONYX_X86_PIC_H

#include <stdint.h>

#define PIC1                 0x20		/* IO base address for master PIC */
#define PIC2                 0xA0		/* IO base address for slave PIC */
#define PIC1_COMMAND         PIC1
#define PIC1_DATA            (PIC1 + 1)
#define PIC2_COMMAND         PIC2
#define PIC2_DATA            (PIC2 + 1)
#define PIC_READ_IRR         0x0a
#define PIC_READ_ISR         0x0b
#define PIC_EOI              0x20		/* End-of-interrupt command code */

void pic_disable(void);
void pic_remap(void);
void pic_unmask_irq(uint16_t irqn);
void pic_mask_irq(uint16_t irqn);
void pic_send_eoi(unsigned char irqn);
uint16_t pic_get_irr(void);
uint16_t pic_get_isr(void);

#endif
