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
#include <kernel/pic.h>
#include <stdint.h>
#include <kernel/portio.h>
static uint16_t __pic_get_irq_reg(int ocw3)
{
	/* OCW3 to PIC CMD to get the register values.  PIC2 is chained, and
	* represents IRQs 8-15.  PIC1 is IRQs 0-7, with 2 being the chain */
	outb(PIC1_COMMAND, ocw3);
	outb(PIC2_COMMAND, ocw3);
	return (inb(PIC2_COMMAND) << 8) | inb(PIC1_COMMAND);
}
/* Disables the PIC */
void pic_disable()
{
	outb(0xa1, 0xFF);
	outb(0x21, 0xFF);
}
/* Remaps the PIC */
void pic_remap()
{
	outb(0x20, 0x11);
	io_wait();
	outb(0xA0, 0x11);
	io_wait();
	outb(0x21, 0x20);
	io_wait();
	outb(0xA1, 0x28);
	io_wait();
	outb(0x21, 0x04);
	io_wait();
	outb(0xA1, 0x02);
	io_wait();
	outb(0x21, 0x01);
	io_wait();
	outb(0xA1, 0x01);
	io_wait();
	outb(0x21, 0x0);
	io_wait();
	outb(0xA1, 0x0);
}
/* Unmask an irq line on the PIC (they are by default all masked) */
void pic_unmask_irq(uint16_t irqn)
{
	uint16_t port;
	uint8_t value;

	if(irqn < 8) {
		port = PIC1_DATA;
	} else {
		port = PIC2_DATA;
		irqn -= 8;
	}
	value = inb(port) & ~(1 << irqn);
	outb(port, value);
}
/* Mask an irq line on the PIC (they are by default all masked) */
void pic_mask_irq(uint16_t irqn)
{
	uint16_t port;
	uint8_t value;
	if(irqn < 8) {
		port = PIC1_DATA;
	} else {
		port = PIC2_DATA;
		irqn -= 8;
	}
	value = inb(port) | (1 << irqn);
	outb(port, value);
}

/* Returns the combined value of the cascaded PICs irq request register */
uint16_t pic_get_irr(void)
{
    return __pic_get_irq_reg(PIC_READ_IRR);
}
void pic_send_eoi(unsigned char irq)
{
	if(irq >= 8)
		outb(PIC2_COMMAND,PIC_EOI);

	outb(PIC1_COMMAND,PIC_EOI);
}
/* Returns the combined value of the cascaded PICs in-service register */
uint16_t pic_get_isr(void)
{
    return __pic_get_irq_reg(PIC_READ_ISR);
}
