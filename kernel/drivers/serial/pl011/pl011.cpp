/*
 * Copyright (c) 2023 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "pl011.h"

#include <onyx/console.h>
#include <onyx/cpu.h>
#include <onyx/serial.h>

void pl011_dev::putc(char c)
{
    while (read<u32>(UARTFR) & UARTFR_TXFF)
        cpu_relax();
    write<u32>(UARTDR, c);
}
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

    spin_lock(&lock_);
    for (size_t i = 0; i < size; i++, buf++)
        putc(*buf);
    spin_unlock(&lock_);
    return size;
}

int pl011_dev::write_console(const void *buf, size_t len, unsigned int flags)
{
    if (flags & (CONSOLE_WRITE_ATOMIC | CONSOLE_WRITE_PANIC))
    {
        if (!(flags & CONSOLE_WRITE_PANIC) && spin_try_lock(&lock_))
            return -EAGAIN;
    }
    else
        spin_lock(&lock_);

    for (size_t i = 0; i < len; i++)
    {
        auto byte = static_cast<uint8_t>(*((char *) buf + i));

        // Needed for basic printing as a debug console
        if (byte == '\n') [[unlikely]]
            putc('\r');
        putc(byte);
    }

    if (!(flags & CONSOLE_WRITE_PANIC))
        spin_unlock(&lock_);
    return 0;
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

static int pl011_write_con(const char *buf, size_t len, unsigned int flags, struct console *con)
{
    pl011_dev *port = (pl011_dev *) con->priv;

    return port->write_console(buf, len, flags);
}

static const struct console_ops pl011_con_ops = {
    .write = pl011_write_con,
};

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

    con = (struct console *) kmalloc(sizeof(*con), GFP_KERNEL);
    console_init(con, "pl011", &pl011_con_ops);
    con->priv = this;
    con_register(con);
    // TODO(pedro): Configure baud rate
    return true;
}

void pl011_dev::set_baud_rate(uint16_t rate)
{
}
