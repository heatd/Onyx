/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include "pl011.h"

#include <onyx/cpu.h>

/**
 * @brief Write bytes to the serial port
 *
 * @param buffer Buffer
 * @param size Length
 * @return Positive byte count or negative error code
 */
ssize_t pl011_dev::write_serial(const void *buffer, size_t size)
{
    const u8 *buf = (const u8 *) buffer;
    for (size_t i = 0; i < size; i++, buf++)
    {
        while (read<u32>(UARTFR) & UARTFR_TXFF)
            cpu_relax();
        write<u32>(UARTDR, *buf);
    }

    return size;
}

irqstatus_t pl011_dev::on_irq()
{
    auto istatus = read<u32>(UARTMIS);

    if (!istatus)
        return IRQ_UNHANDLED;

    if (istatus & UARTIMSC_RXIM)
    {
        // While we have data to read (RX not empty), keep reading and doing receive_byte.
        while (!(read<u32>(UARTFR) & UARTFR_RXFE))
        {
            auto data = (u8) read<uint16_t>(UARTDR);
            receive_byte(data);
        }

        // Clear the RXIM IRQ reason
        write<u32>(UARTICR, UARTIMSC_RXIM);
    }

    return IRQ_HANDLED;
}

irqstatus_t pl011_irq(irq_context *ctx, void *cookie)
{
    auto port = reinterpret_cast<pl011_dev *>(cookie);

    return port->on_irq();
}

bool pl011_dev::init()
{
    // Enable the UART, RX and TX
    write<u32>(UARTCR, UARTCR_RXE | UARTCR_TRE | UARTCR_UARTEN);

    // Enable RX interrupts
    write<u32>(UARTIMSC, UARTIMSC_RXIM);

    // 8 bit words, FIFO enabled
    auto lcr = read<u16>(UARTLCR_H);
    lcr &= ~UARTLCR_H_WLEN_MASK;
    lcr |= UARTLCR_H_FEN;
    lcr |= UARTLCR_H_WLEN_8BITS;
    write<u16>(UARTLCR_H, lcr);

    if (!init_tty())
        return false;

    // TODO(pedro): properly handle irqs
    if (install_irq(33, pl011_irq, dev_, IRQ_FLAG_REGULAR, this) < 0)
        return false;

    // TODO(pedro): Configure baud rate
    return true;
}

void pl011_dev::set_baud_rate(uint16_t rate)
{
}
