/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include <onyx/irq.h>
#include <onyx/portio.h>
#include <onyx/pit.h>
#include <onyx/pic.h>
#include <onyx/compiler.h>
#include <onyx/dev.h>

static volatile uint64_t timer_ticks = 0;

struct driver pit_driver = 
{
	.name = "pit"
};

struct device pit_dev = 
{
	.name = "pit"
};

irqstatus_t pit_irq(struct irq_context *ctx, void *cookie)
{
	timer_ticks++;
	return IRQ_HANDLED;
}

void pit_init(uint32_t frequency)
{
	driver_register_device(&pit_driver, &pit_dev);

	int divisor = 1193180 / frequency;

	/* Install the IRQ handler */
	assert(install_irq(2, pit_irq, &pit_dev, IRQ_FLAG_REGULAR, NULL) == 0);

	outb(0x43, 0x34);
	io_wait();
	outb(0x40, divisor & 0xFF);   // Set low byte of divisor
	io_wait();
	outb(0x40, divisor >> 8);     // Set high byte of divisor
	io_wait();
}

void pit_deinit()
{
	outb(0x42, 0x34);
	free_irq(2, &pit_dev);
}

uint64_t pit_get_tick_count()
{
	return (uint64_t) timer_ticks;
}
