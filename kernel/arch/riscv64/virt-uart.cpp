/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

// Very temporary thing, since the virt machine's UART is a 16650
// for which we already have a driver (uart8250)

#include <stdint.h>
#include <stddef.h>

#include <onyx/serial.h>

volatile uint8_t *uart_base = (volatile uint8_t *) 0x10000000;

static inline uint8_t uart_read_8(size_t offset) {
    return uart_base[offset];
}

static inline void uart_write_8(size_t offset, uint8_t val) {
    uart_base[offset] = val;
}

void platform_serial_init(void)
{
}

void serial_putc(char c)
{
    while ((uart_read_8(5) & (1<<6)) == 0)
        ;
    uart_write_8(0, c);
}

void platform_serial_write(const char *s, size_t size)
{
    for (size_t i = 0; i < size; i++)
	{
        // We need to do this since we have no tty layer before us to deal with this translation
        if (s[i] == '\n')
            serial_putc('\r');
        serial_putc(s[i]);
    }
}
