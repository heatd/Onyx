/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_PL011_H
#define _ONYX_PL011_H

#include <stdint.h>

#include <onyx/dev.h>
#include <onyx/dpc.h>
#include <onyx/driver.h>
#include <onyx/irq.h>
#include <onyx/serial.h>
#include <onyx/tty.h>

#include <onyx/hwregister.hpp>

enum pl011_register
{
    UARTDR = 0,
    UARTRSR = 4,
    UARTFR = 0x18,
    UARTIBRD = 0x24,
    UARTLCR_H = 0x2c,
    UARTCR = 0x30,
    UARTIMSC = 0x38,
    UARTMIS = 0x40,
    UARTICR = 0x44
};

// Transmit FIFO full
#define UARTFR_TXFF (1u << 5)
// RX FIFO empty
#define UARTFR_RXFE (1u << 4)

// RX enable
#define UARTCR_RXE    (1u << 9)
// TX enable
#define UARTCR_TRE    (1u << 8)
// UART enable
#define UARTCR_UARTEN (1u << 0)

// RX interrupt mask
#define UARTIMSC_RXIM (1u << 4)

#define UARTLCR_H_WLEN_MASK  (0b11 << 5)
#define UARTLCR_H_WLEN_8BITS (0b11 << 5)
#define UARTLCR_H_FEN        (1u << 4)

class pl011_dev : public serial_port
{
    hw_range range;
    unsigned int irq_;
    spinlock lock_;
    device *dev_;

    static constexpr uint32_t serial_clock = 115200;
    static constexpr uint16_t default_baud_rate = 38400;

    template <typename T>
    T read(pl011_register reg)
    {
        return range.read<T>((hw_range::register_offset) reg);
    }

    template <typename T>
    void write(pl011_register reg, T val)
    {
        range.write((hw_range::register_offset) reg, val);
    }

    void set_baud_rate(uint16_t rate) override;

public:
    pl011_dev(uint16_t io_port, unsigned int irq, device *dev)
        : range{io_port}, irq_{irq}, lock_{}, dev_{dev}
    {
    }

    pl011_dev(volatile void *mmio, unsigned int irq, device *dev)
        : range{mmio}, irq_{irq}, lock_{}, dev_{dev}
    {
    }

    virtual ~pl011_dev() = default;

    /**
     * @brief Initialises the serial port as a standard serial port
     *
     * @return True if success, else false
     */
    bool init();

    /**
     * @brief Write bytes to the serial port
     *
     * @param buffer Buffer
     * @param size Length
     * @return Positive byte count or negative error code
     */
    ssize_t write_serial(const void *buffer, size_t size) override;

    irqstatus_t on_irq();
};

#endif
