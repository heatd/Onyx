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
#include <kernel/irq.h>
#include <kernel/portio.h>
#include <kernel/pit.h>
#include <kernel/pic.h>
#include <stdint.h>
#include <kernel/compiler.h>
#include <stdio.h>
static volatile uint64_t timer_ticks = 0;
void timer_handler()
{
	timer_ticks++;
}
void pit_init(uint32_t frequency)
{
	int divisor = 1193180 / frequency;

	outb(0x43, 0x36);
	io_wait();
	outb(0x40, divisor & 0xFF);   // Set low byte of divisor
	io_wait();
	outb(0x40, divisor >> 8);     // Set high byte of divisor
	io_wait();
	pic_unmask_irq(0); // Unmask IRQ0 (PIT)

	irq_t handler = &timer_handler;
	// Install the IRQ handler
	irq_install_handler(0,handler);
}

uint64_t get_tick_count()
{
	return (uint64_t)timer_ticks;
}
