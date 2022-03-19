/*
 * Copyright (c) 2020 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_UART8250_H
#define _ONYX_UART8250_H

#include <stdint.h>

#include <onyx/dev.h>
#include <onyx/dpc.h>
#include <onyx/driver.h>
#include <onyx/irq.h>
#include <onyx/port_io.h>
#include <onyx/serial.h>
#include <onyx/tty.h>

enum class uart8250_register
{
    data = 0,
    interrupt_enable = 1,
    /* When DLAB is set, regs 0 and 1 get re-assigned to lsb and msb of the divisor */
    lsb_divisor = 0,
    msb_divisor = 1,
    fifo_control,
    interrupt_identification = 2, /* It's FCR when written, IIR when read */
    line_control,
    modem_control,
    line_status,
    modem_status,
    scratch_register
};

#define UART8250_LCR_DLAB           (1 << 7)
#define UART8250_LCR_SBE            (1 << 6)
#define UART8250_LCR_2_STOP_BITS    (1 << 2)
#define UART8250_LCR_WORD_LENGTH(x) (x << 0)
#define UART8250_LCR_8BIT_WL        3
#define UART8250_LCR_7BIT_WL        2
#define UART8250_LCR_6BIT_WL        1
#define UART8250_LCR_5BIT_WL        0

#define UART8250_FCR_FIFO_ENABLE        (1 << 0)
#define UART8250_FCR_CLR_RCV_FIFO       (1 << 1)
#define UART8250_FCR_CLR_TX_FIFO        (1 << 2)
#define UART8250_FCR_DMA_MODE_SEL       (1 << 3)
#define UART8250_FCR_EN_64B_FIFO        (1 << 5)
#define UART8250_FCR_INT_TRIGGER_4BYTE  (1 << 6)
#define UART8250_FCR_INT_TRIGGER_8BYTE  (2 << 6)
#define UART8250_FCR_INT_TRIGGER_14BYTE (3 << 6)

#define UART8250_MCR_DATA_TERMINAL_RDY (1 << 0)
#define UART8250_MCR_REQ_TO_SEND       (1 << 1)
#define UART8250_MCR_GPO2_ENABLE       (1 << 3)
#define UART8250_MCR_LOOPBACK          (1 << 4)

#define UART8250_LSR_DATA_RDY     (1 << 0)
#define UART8250_LSR_OVERRUN_ERR  (1 << 1)
#define UART8250_LSR_PARITY_ERR   (1 << 2)
#define UART8250_LSR_FRAMING_ERR  (1 << 3)
#define UART8250_LSR_BREAK_INDIC  (1 << 4)
#define UART8250_LSR_TX_BUF_EMPTY (1 << 5)
#define UART8250_LSR_TX_EMPTY     (1 << 6)

#define UART8250_IER_DATA_AVAIL  (1 << 0)
#define UART8250_IER_TX_EMPTY    (1 << 1)
#define UART8250_IER_ERR         (1 << 2)
#define UART8250_IER_STATUS_CHNG (1 << 3)

#define UART8250_IIR_IRQ_PENDING (1 << 0)
#define UART8250_IIR_REASON(x)   (x & (0x7 << 1))
#define UART8250_IIR_RX_DATA_AVL (1 << 2)

class uart8250_port : public serial_port
{
    uint16_t io_port;
    unsigned int irq_;
    spinlock lock_;
    device *dev_;

    static constexpr uint32_t serial_clock = 115200;
    static constexpr uint16_t default_baud_rate = 38400;

    template <typename T>
    T read(uart8250_register reg)
    {
        auto port = io_port + static_cast<uint16_t>(reg);

        static_assert(sizeof(T) <= 4, "Can't do reads larger than 4-bytes long");

        if constexpr (sizeof(T) == 1)
            return inb(port);
        else if constexpr (sizeof(T) == 2)
            return inw(port);
        else if constexpr (sizeof(T) == 4)
            return inl(port);
    }

    template <typename T>
    void write(uart8250_register reg, T val)
    {
        auto port = io_port + static_cast<uint16_t>(reg);

        static_assert(sizeof(T) <= 4, "Can't do writes larger than 4-bytes long");

        if constexpr (sizeof(T) == 1)
            outb(port, val);
        else if constexpr (sizeof(T) == 2)
            outw(port, val);
        else if constexpr (sizeof(T) == 4)
            outl(port, val);
    }

    static constexpr uint16_t calculate_divisor(uint16_t rate)
    {
        return serial_clock / rate;
    }

    bool tx_empty();
    bool rx_rdy();

    void write_byte(uint8_t byte);
    void set_baud_rate(uint16_t rate) override;

    bool present();
    bool test();

    void dispatch_rx();

public:
    uart8250_port(uint16_t io_port, unsigned int irq, device *dev)
        : io_port{io_port}, irq_{irq}, lock_{}, dev_{dev}
    {
    }

    virtual ~uart8250_port()
    {
    }

    /**
     * @brief Initialises the serial port as a debug console
     *
     * @return True if success, else false.
     */
    bool early_init();

    /**
     * @brief Initialises the serial port as a standard serial port
     *
     * @return True if success, else false
     */
    bool init();

    void write(const char *s, size_t length, bool is_debug_console = false);

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
