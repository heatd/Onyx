/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include "uart8250.h"

#include <stdint.h>

#include <onyx/dev.h>
#include <onyx/dpc.h>
#include <onyx/driver.h>
#include <onyx/irq.h>
#include <onyx/panic.h>
#include <onyx/port_io.h>
#include <onyx/serial.h>
#include <onyx/tty.h>

static driver serial_platform_driver = {.name = "uart8250-platform",
                                        .bus_type_node = {&serial_platform_driver}};

device uart8250_platform_device{"uart8250", nullptr, nullptr};

irqstatus_t uart8250_port::on_irq()
{
    auto st = read<uint8_t>(uart8250_register::interrupt_identification);

    if (st & UART8250_IIR_IRQ_PENDING)
        return IRQ_UNHANDLED;

    auto reason = UART8250_IIR_REASON(st);
    if (reason & UART8250_IIR_RX_DATA_AVL)
    {
        auto data = read<uint8_t>(uart8250_register::data);
        receive_byte(data);
        return IRQ_HANDLED;
    }

    return IRQ_UNHANDLED;
}

void uart8250_port::set_baud_rate(uint16_t rate)
{
    auto div_value = calculate_divisor(rate);

    assert(div_value != 0);

    uint8_t old_val = read<uint8_t>(uart8250_register::line_control);
    write<uint8_t>(uart8250_register::line_control, old_val | UART8250_LCR_DLAB);
    write<uint8_t>(uart8250_register::lsb_divisor, div_value & 0xff);
    write<uint8_t>(uart8250_register::msb_divisor, div_value >> 8);

    write<uint8_t>(uart8250_register::line_control, old_val);
}

bool uart8250_port::test()
{
    write<uint8_t>(uart8250_register::modem_control, UART8250_MCR_LOOPBACK);
    write<uint8_t>(uart8250_register::data, 0xcd);

    return read<uint8_t>(uart8250_register::data) == 0xcd;
}

bool uart8250_port::tx_empty()
{
    return read<uint8_t>(uart8250_register::line_status) & UART8250_LSR_TX_BUF_EMPTY;
}

bool uart8250_port::rx_rdy()
{
    return read<uint8_t>(uart8250_register::line_status) & UART8250_LSR_DATA_RDY;
}

void uart8250_port::write_byte(uint8_t c)
{
    int st = do_with_timeout(
        [&]() -> expected<int, int> {
            if (tx_empty())
                return 0;
            return 1;
        },
        NS_PER_MS);

    if (st < 0)
        return;

    write<uint8_t>(uart8250_register::data, c);
}

void uart8250_port::write(const char *s, size_t size, bool is_debug_console)
{
    scoped_lock g{lock_};
    for (size_t i = 0; i < size; i++)
    {
        auto byte = static_cast<uint8_t>(s[i]);

        // Needed for basic printing as a debug console
        if (is_debug_console && byte == '\n') [[unlikely]]
            write_byte('\r');
        write_byte(static_cast<uint8_t>(*(s + i)));
    }
}

bool uart8250_port::present()
{
    static constexpr uint8_t test_val = 0xcd;
    write<uint8_t>(uart8250_register::scratch_register, test_val);

    auto present = read<uint8_t>(uart8250_register::scratch_register);

    return present == test_val;
}

irqstatus_t uart8250_irq(irq_context *ctx, void *cookie)
{
    auto port = reinterpret_cast<uart8250_port *>(cookie);

    return port->on_irq();
}

/**
 * @brief Initialises the serial port as a debug console
 *
 * @return True if success, else false.
 */
bool uart8250_port::early_init()
{
    /* Disable interrupts */
    write<uint8_t>(uart8250_register::interrupt_enable, 0);

    /* Then we set the baud rate of the port */
    set_baud_rate(default_baud_rate);

    /* Set the word length to 8-bits per word */
    write<uint8_t>(uart8250_register::line_control, UART8250_LCR_WORD_LENGTH(UART8250_LCR_8BIT_WL));

    /* Set some FIFO settings */
    uint8_t fcr = UART8250_FCR_CLR_TX_FIFO | UART8250_FCR_CLR_RCV_FIFO | UART8250_FCR_FIFO_ENABLE |
                  UART8250_FCR_INT_TRIGGER_14BYTE;

    write<uint8_t>(uart8250_register::fifo_control, fcr);

    /* Signal that we're ready to send and ready to receive */
    // Note: UART8250_MCR_GPO2_ENABLE = Enable interrupts as well. It's weird, but we also need to
    // set this.
    write<uint8_t>(uart8250_register::modem_control, UART8250_MCR_GPO2_ENABLE |
                                                         UART8250_MCR_DATA_TERMINAL_RDY |
                                                         UART8250_MCR_REQ_TO_SEND);

    return true;
}

/**
 * @brief Write bytes to the serial port
 *
 * @param buffer Buffer
 * @param size Length
 * @return Positive byte count or negative error code
 */
ssize_t uart8250_port::write_serial(const void *buffer, size_t size)
{
    write((const char *) buffer, size);
    return size;
}

/**
 * @brief Initialises the serial port as a standard serial port
 *
 * @return True if success, else false
 */
bool uart8250_port::init()
{
    if (!early_init())
        return false;

    install_irq(irq_, uart8250_irq, dev_, IRQ_FLAG_REGULAR, this);

    /* Re-enable interrupts */
    write<uint8_t>(uart8250_register::interrupt_enable, UART8250_IER_DATA_AVAIL);

    return init_tty();
}

#ifdef __x86_64__

alignas(uart8250_port) static char com1_buf[sizeof(uart8250_port)];
uart8250_port *com1;

void platform_serial_init(void)
{
    com1 = new (com1_buf) uart8250_port{0x3f8, 4, &uart8250_platform_device};
    com1->early_init();
    uart8250_platform_device.driver_ = &serial_platform_driver;
}

void platform_serial_write(const char *s, size_t size)
{
    com1->write(s, size, true);
}

#endif
