/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
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
uintptr_t timer_handler(registers_t *regs)
{
	timer_ticks++;
	return 0;
}
void pit_init(uint32_t frequency)
{
	int divisor = 1193180 / frequency;

	outb(0x43, 0x34);
	io_wait();
	outb(0x40, divisor & 0xFF);   // Set low byte of divisor
	io_wait();
	outb(0x40, divisor >> 8);     // Set high byte of divisor
	io_wait();
	irq_t handler = &timer_handler;
	// Install the IRQ handler
	irq_install_handler(2, handler);
}
void pit_deinit()
{
	outb(0x42, 0x34);
	irq_uninstall_handler(2, timer_handler);
}
uint64_t pit_get_tick_count()
{
	return (uint64_t)timer_ticks;
}
